// SPDX-License-Identifier: GPL-2.0-or-later
// psemu native GNM backend: run translated PS4 shaders on the host GPU.
//
// One gnm_draw() call builds a complete Vulkan graphics pipeline from a GNM
// VS/PS pair, binds the resources those shaders reference (read straight from
// host memory through the descriptors in their user data), draws once into an
// RGBA8 target and reads the pixels back. It is deliberately simple - every
// object is created and destroyed per draw - so it can serve as the reference
// path while a PM4 command processor and caching layer are built on top.
#define VULKAN_HPP_DISPATCH_LOADER_DYNAMIC 1
#define VULKAN_HPP_NO_STRUCT_CONSTRUCTORS
#include <windows.h>
#include <vulkan/vulkan.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <deque>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <fmt/format.h>

#include "gnm_internal.h"
#include "gnm_tiling.h"
#include "shader_recompiler/backend/spirv/emit_spirv_quad_rect.h"
#include "shader_recompiler/frontend/fetch_shader.h"
#include "video_core/amdgpu/resource.h"

VULKAN_HPP_DEFAULT_DISPATCH_LOADER_DYNAMIC_STORAGE

namespace psemu {

namespace {

struct Device {
    HMODULE lib{};
    vk::Instance instance;
    vk::PhysicalDevice phys;
    vk::Device dev;
    vk::Queue queue;
    u32 queue_family{};
    vk::CommandPool cmd_pool;
    vk::PhysicalDeviceMemoryProperties mem_props;
    std::string name;
    Shader::Profile profile;
    bool tessellation{};      // tessellationShader feature enabled (RectList/QuadList)
};

std::mutex g_mutex;
std::optional<Device> g_dev;
const Shader::Profile g_default_profile = DefaultProfile();

[[noreturn]] void Fail(const std::string& msg) {
    throw std::runtime_error(msg);
}

bool HasExt(const std::vector<vk::ExtensionProperties>& exts, const char* name) {
    return std::any_of(exts.begin(), exts.end(),
                       [&](const auto& e) { return std::strcmp(e.extensionName, name) == 0; });
}

void InitDevice() {
    Device d;
    d.lib = LoadLibraryA("vulkan-1.dll");
    if (!d.lib) {
        Fail("vulkan-1.dll not found (install a Vulkan-capable GPU driver)");
    }
    auto gipa = reinterpret_cast<PFN_vkGetInstanceProcAddr>(
        GetProcAddress(d.lib, "vkGetInstanceProcAddr"));
    VULKAN_HPP_DEFAULT_DISPATCHER.init(gipa);

    const vk::ApplicationInfo app{.pApplicationName = "psemu-gnm",
                                  .applicationVersion = 1,
                                  .pEngineName = "psemu",
                                  .engineVersion = 1,
                                  .apiVersion = VK_API_VERSION_1_3};
    std::vector<const char*> layers;
    if (const char* v = std::getenv("PSEMU_VK_VALIDATION"); v && *v == '1') {
        layers.push_back("VK_LAYER_KHRONOS_validation");
    }
    d.instance = vk::createInstance({.pApplicationInfo = &app,
                                     .enabledLayerCount = u32(layers.size()),
                                     .ppEnabledLayerNames = layers.data()});
    VULKAN_HPP_DEFAULT_DISPATCHER.init(d.instance);

    const auto phys = d.instance.enumeratePhysicalDevices();
    if (phys.empty()) {
        Fail("no Vulkan physical device");
    }
    d.phys = phys[0];
    for (const auto& p : phys) {
        if (p.getProperties().deviceType == vk::PhysicalDeviceType::eDiscreteGpu) {
            d.phys = p;
            break;
        }
    }
    const auto props = d.phys.getProperties();
    if (props.apiVersion < VK_API_VERSION_1_3) {
        Fail(fmt::format("{} only supports Vulkan {}.{}; 1.3 is required",
                         props.deviceName.data(), VK_API_VERSION_MAJOR(props.apiVersion),
                         VK_API_VERSION_MINOR(props.apiVersion)));
    }
    d.name = props.deviceName.data();
    d.mem_props = d.phys.getMemoryProperties();

    const auto qfs = d.phys.getQueueFamilyProperties();
    bool found = false;
    for (u32 i = 0; i < qfs.size(); ++i) {
        if (qfs[i].queueFlags & vk::QueueFlagBits::eGraphics) {
            d.queue_family = i;
            found = true;
            break;
        }
    }
    if (!found) {
        Fail("no graphics queue");
    }

    // ---- features: enable whatever the recompiler may emit and the GPU has
    const auto avail_chain = d.phys.getFeatures2<vk::PhysicalDeviceFeatures2,
                                                 vk::PhysicalDeviceVulkan11Features,
                                                 vk::PhysicalDeviceVulkan12Features,
                                                 vk::PhysicalDeviceVulkan13Features>();
    const auto& a10 = avail_chain.get<vk::PhysicalDeviceFeatures2>().features;
    const auto& a11 = avail_chain.get<vk::PhysicalDeviceVulkan11Features>();
    const auto& a12 = avail_chain.get<vk::PhysicalDeviceVulkan12Features>();
    const auto& a13 = avail_chain.get<vk::PhysicalDeviceVulkan13Features>();
    if (!a13.dynamicRendering) {
        Fail("GPU driver lacks dynamicRendering");
    }
    vk::PhysicalDeviceVulkan13Features f13{.shaderDemoteToHelperInvocation =
                                               a13.shaderDemoteToHelperInvocation,
                                           .synchronization2 = a13.synchronization2,
                                           .dynamicRendering = VK_TRUE,
                                           .maintenance4 = a13.maintenance4};
    vk::PhysicalDeviceVulkan12Features f12{
        .pNext = &f13,
        .storageBuffer8BitAccess = a12.storageBuffer8BitAccess,
        .uniformAndStorageBuffer8BitAccess = a12.uniformAndStorageBuffer8BitAccess,
        .shaderFloat16 = a12.shaderFloat16,
        .shaderInt8 = a12.shaderInt8,
        .scalarBlockLayout = a12.scalarBlockLayout,
        .uniformBufferStandardLayout = a12.uniformBufferStandardLayout,
        .shaderSubgroupExtendedTypes = a12.shaderSubgroupExtendedTypes,
        .separateDepthStencilLayouts = a12.separateDepthStencilLayouts,
        .hostQueryReset = a12.hostQueryReset,
        .timelineSemaphore = a12.timelineSemaphore,
        .vulkanMemoryModel = a12.vulkanMemoryModel,
        .vulkanMemoryModelDeviceScope = a12.vulkanMemoryModelDeviceScope,
    };
    vk::PhysicalDeviceVulkan11Features f11{
        .pNext = &f12,
        .storageBuffer16BitAccess = a11.storageBuffer16BitAccess,
        .uniformAndStorageBuffer16BitAccess = a11.uniformAndStorageBuffer16BitAccess,
        .shaderDrawParameters = a11.shaderDrawParameters,
    };
    vk::PhysicalDeviceFeatures f10{};
    f10.imageCubeArray = a10.imageCubeArray;
    f10.independentBlend = a10.independentBlend;
    f10.geometryShader = a10.geometryShader;
    f10.tessellationShader = a10.tessellationShader;
    f10.sampleRateShading = a10.sampleRateShading;
    f10.dualSrcBlend = a10.dualSrcBlend;
    f10.depthClamp = a10.depthClamp;
    f10.fillModeNonSolid = a10.fillModeNonSolid;
    f10.samplerAnisotropy = a10.samplerAnisotropy;
    f10.textureCompressionBC = a10.textureCompressionBC;
    f10.vertexPipelineStoresAndAtomics = a10.vertexPipelineStoresAndAtomics;
    f10.fragmentStoresAndAtomics = a10.fragmentStoresAndAtomics;
    f10.shaderImageGatherExtended = a10.shaderImageGatherExtended;
    f10.shaderStorageImageExtendedFormats = a10.shaderStorageImageExtendedFormats;
    f10.shaderStorageImageReadWithoutFormat = a10.shaderStorageImageReadWithoutFormat;
    f10.shaderStorageImageWriteWithoutFormat = a10.shaderStorageImageWriteWithoutFormat;
    f10.shaderClipDistance = a10.shaderClipDistance;
    f10.shaderCullDistance = a10.shaderCullDistance;
    f10.shaderFloat64 = a10.shaderFloat64;
    f10.shaderInt64 = a10.shaderInt64;
    f10.shaderInt16 = a10.shaderInt16;
    const vk::PhysicalDeviceFeatures2 f2{.pNext = &f11, .features = f10};

    const auto exts = d.phys.enumerateDeviceExtensionProperties();
    std::vector<const char*> enable;
    const auto want = [&](const char* e) {
        if (HasExt(exts, e)) {
            enable.push_back(e);
            return true;
        }
        return false;
    };
    const bool amd_lod = want(VK_AMD_SHADER_IMAGE_LOAD_STORE_LOD_EXTENSION_NAME);
    const bool amd_gcn = want(VK_AMD_GCN_SHADER_EXTENSION_NAME);
    const bool amd_minmax = want(VK_AMD_SHADER_TRINARY_MINMAX_EXTENSION_NAME);
    const bool amd_evp = want(VK_AMD_SHADER_EXPLICIT_VERTEX_PARAMETER_EXTENSION_NAME);

    const float prio = 1.0f;
    const vk::DeviceQueueCreateInfo qci{.queueFamilyIndex = d.queue_family,
                                        .queueCount = 1,
                                        .pQueuePriorities = &prio};
    d.dev = d.phys.createDevice({.pNext = &f2,
                                 .queueCreateInfoCount = 1,
                                 .pQueueCreateInfos = &qci,
                                 .enabledExtensionCount = u32(enable.size()),
                                 .ppEnabledExtensionNames = enable.data()});
    VULKAN_HPP_DEFAULT_DISPATCHER.init(d.dev);
    d.queue = d.dev.getQueue(d.queue_family, 0);
    d.cmd_pool = d.dev.createCommandPool(
        {.flags = vk::CommandPoolCreateFlagBits::eResetCommandBuffer,
         .queueFamilyIndex = d.queue_family});

    // ---- profile from what is really enabled
    const auto pchain = d.phys.getProperties2<vk::PhysicalDeviceProperties2,
                                              vk::PhysicalDeviceVulkan11Properties,
                                              vk::PhysicalDeviceVulkan12Properties>();
    const auto& lim = props.limits;
    const auto& p11 = pchain.get<vk::PhysicalDeviceVulkan11Properties>();
    const auto& p12 = pchain.get<vk::PhysicalDeviceVulkan12Properties>();
    d.tessellation = a10.tessellationShader;
    auto& p = d.profile;
    p = Shader::Profile{};
    p.max_ubo_size = lim.maxUniformBufferRange - u32(lim.minUniformBufferOffsetAlignment);
    p.max_viewport_width = lim.maxViewportDimensions[0];
    p.max_viewport_height = lim.maxViewportDimensions[1];
    p.max_shared_memory_size = lim.maxComputeSharedMemorySize;
    p.supported_spirv = 0x00010600;
    p.subgroup_size = p11.subgroupSize;
    p.support_int8 = f12.shaderInt8;
    p.support_int16 = f10.shaderInt16;
    p.support_int64 = f10.shaderInt64;
    p.support_float16 = f12.shaderFloat16;
    p.support_float64 = f10.shaderFloat64;
    using Indep = vk::ShaderFloatControlsIndependence;
    p.supports_denorm_behavior_independence = p12.denormBehaviorIndependence != Indep::eNone;
    p.supports_rounding_mode_independence = p12.roundingModeIndependence != Indep::eNone;
    p.support_fp16_denorm_preserve = p12.shaderDenormPreserveFloat16;
    p.support_fp16_denorm_flush = p12.shaderDenormFlushToZeroFloat16;
    p.support_fp16_round_to_zero = p12.shaderRoundingModeRTZFloat16;
    p.support_fp32_denorm_preserve = p12.shaderDenormPreserveFloat32;
    p.support_fp32_denorm_flush = p12.shaderDenormFlushToZeroFloat32;
    p.support_fp32_round_to_zero = p12.shaderRoundingModeRTZFloat32;
    p.support_fp64_denorm_preserve = p12.shaderDenormPreserveFloat64;
    p.support_fp64_denorm_flush = p12.shaderDenormFlushToZeroFloat64;
    p.support_fp64_round_to_zero = p12.shaderRoundingModeRTZFloat64;
    p.support_fp16_signed_zero_inf_nan_preserve = p12.shaderSignedZeroInfNanPreserveFloat16;
    p.support_fp32_signed_zero_inf_nan_preserve = p12.shaderSignedZeroInfNanPreserveFloat32;
    p.support_fp64_signed_zero_inf_nan_preserve = p12.shaderSignedZeroInfNanPreserveFloat64;
    p.supports_image_load_store_lod = amd_lod;
    p.supports_native_cube_calc = amd_gcn;
    p.supports_trinary_minmax = amd_minmax;
    p.supports_amd_shader_explicit_vertex_parameter = amd_evp;
    p.needs_buffer_offsets = lim.minStorageBufferOffsetAlignment > 4;
    g_dev.emplace(std::move(d));
}

Device& Dev() {
    if (!g_dev) {
        InitDevice();
    }
    return *g_dev;
}

// ------------------------------------------------------------- resources

u32 FindMemory(u32 type_bits, vk::MemoryPropertyFlags want) {
    const auto& mp = Dev().mem_props;
    for (u32 i = 0; i < mp.memoryTypeCount; ++i) {
        if ((type_bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & want) == want) {
            return i;
        }
    }
    Fail("no suitable GPU memory type");
}

u32 HostMemory(u32 type_bits) {
    using M = vk::MemoryPropertyFlagBits;
    const auto& mp = Dev().mem_props;
    const vk::MemoryPropertyFlags cached = M::eHostVisible | M::eHostCoherent | M::eHostCached;
    for (u32 i = 0; i < mp.memoryTypeCount; ++i) {
        if ((type_bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & cached) == cached) {
            return i;
        }
    }
    return FindMemory(type_bits, M::eHostVisible | M::eHostCoherent);
}

// ------------------------------------------------------------- memory pool
//
// Per-draw scratch (staging buffers, vertex/index buffers, textures) used to
// call vkAllocateMemory/vkFreeMemory once per resource per draw - dozens of
// round-trips a frame, and the costliest part of a submit. Instead carve those
// from a few large VkDeviceMemory blocks and, after each draw's GPU work has
// finished, reset the bump offsets (the blocks stay alive and mapped) so the
// next draw reuses the same memory. Nothing about the resources themselves
// changes - same buffers, same bytes, same copies - so rendering is identical.
//
// Blocks are bucketed by (memoryTypeIndex, linear-vs-optimal) so linear buffers
// and optimal-tiled images never share a block, which keeps us clear of
// bufferImageGranularity aliasing rules without extra padding.
struct PoolBlock {
    vk::DeviceMemory mem;
    vk::DeviceSize size{};
    vk::DeviceSize used{};
    void* map{};
};

struct MemPool {
    u32 key{};             // (memoryTypeIndex << 1) | is_image
    u32 type{};
    bool host{};           // host-visible -> persistently mapped
    std::vector<PoolBlock> blocks;
};

std::vector<MemPool> g_pools;
constexpr vk::DeviceSize kPoolBlock = 128ull << 20;   // 128 MB default block

// Suballocate `size` bytes (aligned) of memory type `type`; `is_image` buckets
// optimal-tiled images apart from linear buffers. Returns (block memory,
// offset) and, for host pools, writes the mapped CPU pointer to *map_out.
std::pair<vk::DeviceMemory, vk::DeviceSize> PoolAlloc(u32 type, bool is_image,
                                                      vk::DeviceSize size, vk::DeviceSize align,
                                                      void** map_out) {
    auto& dev = Dev().dev;
    const u32 key = (type << 1) | (is_image ? 1u : 0u);
    MemPool* pool = nullptr;
    for (auto& p : g_pools) {
        if (p.key == key) { pool = &p; break; }
    }
    if (!pool) {
        const bool host = !is_image;   // buffers come from HostMemory(), images device-local
        g_pools.push_back({.key = key, .type = type, .host = host});
        pool = &g_pools.back();
    }
    align = std::max<vk::DeviceSize>(align, 1);
    for (auto& b : pool->blocks) {
        const vk::DeviceSize off = (b.used + align - 1) & ~(align - 1);
        if (off + size <= b.size) {
            b.used = off + size;
            if (map_out) *map_out = static_cast<u8*>(b.map) + off;
            return {b.mem, off};
        }
    }
    // No room: add a block big enough for this request (at least kPoolBlock).
    PoolBlock nb;
    nb.size = std::max(size, kPoolBlock);
    nb.mem = dev.allocateMemory({.allocationSize = nb.size, .memoryTypeIndex = type});
    if (pool->host) {
        nb.map = dev.mapMemory(nb.mem, 0, VK_WHOLE_SIZE);
    }
    nb.used = size;
    pool->blocks.push_back(nb);
    if (map_out) *map_out = nb.map;
    return {nb.mem, 0};
}

void PoolResetAll() {
    for (auto& p : g_pools) {
        for (auto& b : p.blocks) {
            b.used = 0;
        }
    }
}

void PoolDestroyAll() {
    if (!g_dev) return;
    auto& dev = g_dev->dev;
    for (auto& p : g_pools) {
        for (auto& b : p.blocks) {
            dev.freeMemory(b.mem);   // implicitly unmaps
        }
    }
    g_pools.clear();
}

struct Buffer {
    vk::Buffer buf;
    vk::DeviceMemory mem;   // null when pool-owned (not freed by ~Frame)
    void* map{};
    vk::DeviceSize size{};
};

struct Image {
    vk::Image img;
    vk::DeviceMemory mem;
    vk::ImageView view;
};

// Everything created for one draw; destroyed in the destructor.
// deque, not vector: NewBuffer/NewImage hand out references that callers keep
// (staging/index/vertex buffers), and push_back must not move earlier ones.
struct Frame {
    vk::Device dev;
    std::deque<Buffer> buffers;
    std::deque<Image> images;
    std::vector<vk::Sampler> samplers;
    std::vector<vk::ShaderModule> modules;
    vk::DescriptorSetLayout set_layout;
    vk::PipelineLayout pipe_layout;
    vk::DescriptorPool pool;
    vk::Pipeline pipeline;
    vk::CommandBuffer cmd;
    vk::Fence fence;

    ~Frame() {
        if (fence) dev.destroyFence(fence);
        if (cmd) dev.freeCommandBuffers(Dev().cmd_pool, cmd);
        if (pipeline) dev.destroyPipeline(pipeline);
        if (pool) dev.destroyDescriptorPool(pool);
        if (pipe_layout) dev.destroyPipelineLayout(pipe_layout);
        if (set_layout) dev.destroyDescriptorSetLayout(set_layout);
        for (auto m : modules) dev.destroyShaderModule(m);
        for (auto s : samplers) dev.destroySampler(s);
        for (auto& i : images) {
            if (i.view) dev.destroyImageView(i.view);
            dev.destroyImage(i.img);
            if (i.mem) dev.freeMemory(i.mem);   // pool-owned memory is null here
        }
        for (auto& b : buffers) {
            dev.destroyBuffer(b.buf);
            if (b.mem) dev.freeMemory(b.mem);
        }
        // Pooled memory is NOT reclaimed here: several draws of one submit keep
        // their scratch live at once (they share a command buffer), so the pool
        // is reset only at a submit boundary, when the GPU is idle - see
        // PoolResetAll() in ReleaseSurfaces / the standalone draw+compute paths.
    }

    Buffer& NewBuffer(vk::DeviceSize size, vk::BufferUsageFlags usage) {
        size = std::max<vk::DeviceSize>(size, 16);
        Buffer b;
        b.size = size;
        b.buf = dev.createBuffer({.size = size, .usage = usage});
        const auto req = dev.getBufferMemoryRequirements(b.buf);
        // Prefer host-*cached* memory: the CPU reads these back (render
        // targets, written images/buffers), and scattered reads from
        // write-combined memory (retiling) are ~30x slower.
        const auto [mem, off] = PoolAlloc(HostMemory(req.memoryTypeBits), /*is_image=*/false,
                                          req.size, req.alignment, &b.map);
        b.mem = nullptr;   // pool-owned: ~Frame must not free it
        dev.bindBufferMemory(b.buf, mem, off);
        std::memset(b.map, 0, size);
        buffers.push_back(b);
        return buffers.back();
    }

    Image& NewImage(const vk::ImageCreateInfo& ci) {
        Image im;
        im.img = dev.createImage(ci);
        const auto req = dev.getImageMemoryRequirements(im.img);
        const auto [mem, off] = PoolAlloc(
            FindMemory(req.memoryTypeBits, vk::MemoryPropertyFlagBits::eDeviceLocal),
            /*is_image=*/true, req.size, req.alignment, nullptr);
        im.mem = nullptr;   // pool-owned: ~Frame must not free it
        dev.bindImageMemory(im.img, mem, off);
        images.push_back(im);
        return images.back();
    }
};

// ------------------------------------------------------------- formats

struct FormatInfo {
    vk::Format fmt;
    u32 bytes;   // per texel, or per 4x4 block for BC formats
    bool block;
};

std::optional<FormatInfo> MapFormat(AmdGpu::DataFormat df, AmdGpu::NumberFormat nf) {
    using D = AmdGpu::DataFormat;
    using N = AmdGpu::NumberFormat;
    using F = vk::Format;
    const auto pick = [&](F un, F sn, F ui, F si, F fl, F srgb, u32 bytes)
        -> std::optional<FormatInfo> {
        F f = F::eUndefined;
        switch (nf) {
        case N::Unorm: f = un; break;
        case N::Snorm: case N::SnormNz: f = sn; break;
        case N::Uint: case N::Uscaled: f = ui; break;
        case N::Sint: case N::Sscaled: f = si; break;
        case N::Float: f = fl; break;
        case N::Srgb: f = srgb; break;
        default: break;
        }
        if (f == F::eUndefined) return std::nullopt;
        return FormatInfo{f, bytes, false};
    };
    const F X = F::eUndefined;
    switch (df) {
    case D::Format8:
        return pick(F::eR8Unorm, F::eR8Snorm, F::eR8Uint, F::eR8Sint, X, F::eR8Srgb, 1);
    case D::Format16:
        return pick(F::eR16Unorm, F::eR16Snorm, F::eR16Uint, F::eR16Sint, F::eR16Sfloat, X, 2);
    case D::Format8_8:
        return pick(F::eR8G8Unorm, F::eR8G8Snorm, F::eR8G8Uint, F::eR8G8Sint, X, F::eR8G8Srgb, 2);
    case D::Format32:
        return pick(X, X, F::eR32Uint, F::eR32Sint, F::eR32Sfloat, X, 4);
    case D::Format16_16:
        return pick(F::eR16G16Unorm, F::eR16G16Snorm, F::eR16G16Uint, F::eR16G16Sint,
                    F::eR16G16Sfloat, X, 4);
    case D::Format10_11_11:
        return pick(X, X, X, X, F::eB10G11R11UfloatPack32, X, 4);
    case D::Format2_10_10_10:
        return pick(F::eA2B10G10R10UnormPack32, F::eA2B10G10R10SnormPack32,
                    F::eA2B10G10R10UintPack32, F::eA2B10G10R10SintPack32, X, X, 4);
    case D::Format8_8_8_8:
        return pick(F::eR8G8B8A8Unorm, F::eR8G8B8A8Snorm, F::eR8G8B8A8Uint, F::eR8G8B8A8Sint, X,
                    F::eR8G8B8A8Srgb, 4);
    case D::Format32_32:
        return pick(X, X, F::eR32G32Uint, F::eR32G32Sint, F::eR32G32Sfloat, X, 8);
    case D::Format16_16_16_16:
        return pick(F::eR16G16B16A16Unorm, F::eR16G16B16A16Snorm, F::eR16G16B16A16Uint,
                    F::eR16G16B16A16Sint, F::eR16G16B16A16Sfloat, X, 8);
    case D::Format32_32_32_32:
        return pick(X, X, F::eR32G32B32A32Uint, F::eR32G32B32A32Sint, F::eR32G32B32A32Sfloat, X,
                    16);
    case D::Format5_6_5:
        return pick(F::eB5G6R5UnormPack16, X, X, X, X, X, 2);
    case D::FormatBc1:
        return FormatInfo{nf == N::Srgb ? F::eBc1RgbaSrgbBlock : F::eBc1RgbaUnormBlock, 8, true};
    case D::FormatBc2:
        return FormatInfo{nf == N::Srgb ? F::eBc2SrgbBlock : F::eBc2UnormBlock, 16, true};
    case D::FormatBc3:
        return FormatInfo{nf == N::Srgb ? F::eBc3SrgbBlock : F::eBc3UnormBlock, 16, true};
    case D::FormatBc4:
        return FormatInfo{nf == N::Snorm ? F::eBc4SnormBlock : F::eBc4UnormBlock, 8, true};
    case D::FormatBc5:
        return FormatInfo{nf == N::Snorm ? F::eBc5SnormBlock : F::eBc5UnormBlock, 16, true};
    case D::FormatBc6:
        return FormatInfo{nf == N::Snorm ? F::eBc6HSfloatBlock : F::eBc6HUfloatBlock, 16, true};
    case D::FormatBc7:
        return FormatInfo{nf == N::Srgb ? F::eBc7SrgbBlock : F::eBc7UnormBlock, 16, true};
    default:
        return std::nullopt;
    }
}

// Vertex attribute formats. USCALED/SSCALED attributes reach the shader as
// floats (the recompiler declares them float), so they need the Vulkan
// *scaled* formats rather than the integer ones MapFormat picks for images.
std::optional<vk::Format> VertexFormat(AmdGpu::DataFormat df, AmdGpu::NumberFormat nf) {
    using D = AmdGpu::DataFormat;
    using N = AmdGpu::NumberFormat;
    using F = vk::Format;
    if (nf == N::Uscaled || nf == N::Sscaled) {
        const bool u = nf == N::Uscaled;
        switch (df) {
        case D::Format8: return u ? F::eR8Uscaled : F::eR8Sscaled;
        case D::Format8_8: return u ? F::eR8G8Uscaled : F::eR8G8Sscaled;
        case D::Format8_8_8_8: return u ? F::eR8G8B8A8Uscaled : F::eR8G8B8A8Sscaled;
        case D::Format16: return u ? F::eR16Uscaled : F::eR16Sscaled;
        case D::Format16_16: return u ? F::eR16G16Uscaled : F::eR16G16Sscaled;
        case D::Format16_16_16_16: return u ? F::eR16G16B16A16Uscaled : F::eR16G16B16A16Sscaled;
        case D::Format2_10_10_10:
            return u ? F::eA2B10G10R10UscaledPack32 : F::eA2B10G10R10SscaledPack32;
        default: return std::nullopt;
        }
    }
    if (df == D::Format32_32_32) {
        switch (nf) {
        case N::Float: return F::eR32G32B32Sfloat;
        case N::Uint: return F::eR32G32B32Uint;
        case N::Sint: return F::eR32G32B32Sint;
        default: return std::nullopt;
        }
    }
    if (const auto fi = MapFormat(df, nf); fi && !fi->block) {
        return fi->fmt;
    }
    return std::nullopt;
}

// GCN stencil ops. ADD/SUB_CLAMP/WRAP add the op value on GCN but 1 in
// Vulkan (they agree when DB_STENCILREFMASK.STENCILOPVAL is 1, the usual
// setting); ONES and the bitwise ops have no Vulkan equivalent.
vk::StencilOp MapStencilOp(AmdGpu::StencilFunc f) {
    using S = AmdGpu::StencilFunc;
    switch (f) {
    case S::Keep: return vk::StencilOp::eKeep;
    case S::Zero: return vk::StencilOp::eZero;
    case S::ReplaceTest:
    case S::ReplaceOp: return vk::StencilOp::eReplace;
    case S::AddClamp: return vk::StencilOp::eIncrementAndClamp;
    case S::SubClamp: return vk::StencilOp::eDecrementAndClamp;
    case S::Invert: return vk::StencilOp::eInvert;
    case S::AddWrap: return vk::StencilOp::eIncrementAndWrap;
    case S::SubWrap: return vk::StencilOp::eDecrementAndWrap;
    default: Fail(fmt::format("stencil op {} has no Vulkan equivalent", u32(f)));
    }
}

vk::ComponentSwizzle MapSwizzle(AmdGpu::CompSwizzle s) {
    switch (s) {
    case AmdGpu::CompSwizzle::Zero: return vk::ComponentSwizzle::eZero;
    case AmdGpu::CompSwizzle::One: return vk::ComponentSwizzle::eOne;
    case AmdGpu::CompSwizzle::Red: return vk::ComponentSwizzle::eR;
    case AmdGpu::CompSwizzle::Green: return vk::ComponentSwizzle::eG;
    case AmdGpu::CompSwizzle::Blue: return vk::ComponentSwizzle::eB;
    case AmdGpu::CompSwizzle::Alpha: return vk::ComponentSwizzle::eA;
    }
    return vk::ComponentSwizzle::eIdentity;
}

vk::SamplerAddressMode MapClamp(AmdGpu::ClampMode m) {
    using C = AmdGpu::ClampMode;
    switch (m) {
    case C::Wrap: return vk::SamplerAddressMode::eRepeat;
    case C::Mirror: return vk::SamplerAddressMode::eMirroredRepeat;
    case C::ClampLastTexel: return vk::SamplerAddressMode::eClampToEdge;
    case C::MirrorOnceLastTexel: return vk::SamplerAddressMode::eClampToEdge;
    case C::ClampHalfBorder: case C::ClampBorder: return vk::SamplerAddressMode::eClampToBorder;
    default: return vk::SamplerAddressMode::eClampToEdge;
    }
}

vk::PrimitiveTopology MapPrim(u32 p) {
    switch (p) {
    case GNM_PRIM_POINTLIST: return vk::PrimitiveTopology::ePointList;
    case GNM_PRIM_LINELIST: return vk::PrimitiveTopology::eLineList;
    case GNM_PRIM_LINESTRIP: return vk::PrimitiveTopology::eLineStrip;
    case GNM_PRIM_TRILIST: return vk::PrimitiveTopology::eTriangleList;
    case GNM_PRIM_TRIFAN: return vk::PrimitiveTopology::eTriangleFan;
    case GNM_PRIM_TRISTRIP: return vk::PrimitiveTopology::eTriangleStrip;
    default: Fail(fmt::format("primitive type {:#x} not supported yet", p));
    }
}

vk::BlendFactor MapBlendFactor(AmdGpu::BlendControl::BlendFactor f) {
    using B = AmdGpu::BlendControl::BlendFactor;
    using V = vk::BlendFactor;
    switch (f) {
    case B::Zero: return V::eZero;
    case B::One: return V::eOne;
    case B::SrcColor: return V::eSrcColor;
    case B::OneMinusSrcColor: return V::eOneMinusSrcColor;
    case B::SrcAlpha: return V::eSrcAlpha;
    case B::OneMinusSrcAlpha: return V::eOneMinusSrcAlpha;
    case B::DstAlpha: return V::eDstAlpha;
    case B::OneMinusDstAlpha: return V::eOneMinusDstAlpha;
    case B::DstColor: return V::eDstColor;
    case B::OneMinusDstColor: return V::eOneMinusDstColor;
    case B::SrcAlphaSaturate: return V::eSrcAlphaSaturate;
    case B::ConstantColor: return V::eConstantColor;
    case B::OneMinusConstantColor: return V::eOneMinusConstantColor;
    case B::Src1Color: return V::eSrc1Color;
    case B::InvSrc1Color: return V::eOneMinusSrc1Color;
    case B::Src1Alpha: return V::eSrc1Alpha;
    case B::InvSrc1Alpha: return V::eOneMinusSrc1Alpha;
    case B::ConstantAlpha: return V::eConstantAlpha;
    case B::OneMinusConstantAlpha: return V::eOneMinusConstantAlpha;
    }
    return V::eOne;
}

vk::BlendOp MapBlendOp(AmdGpu::BlendControl::BlendFunc f) {
    using B = AmdGpu::BlendControl::BlendFunc;
    switch (f) {
    case B::Add: return vk::BlendOp::eAdd;
    case B::Subtract: return vk::BlendOp::eSubtract;
    case B::Min: return vk::BlendOp::eMin;
    case B::Max: return vk::BlendOp::eMax;
    case B::ReverseSubtract: return vk::BlendOp::eReverseSubtract;
    }
    return vk::BlendOp::eAdd;
}

bool IsLinear(AmdGpu::TileMode m) {
    return m == AmdGpu::TileMode::DisplayLinearAligned ||
           m == AmdGpu::TileMode::DisplayLinearGeneral;
}

// ------------------------------------------------------------- execution

struct PendingUpload {
    vk::Image img;
    vk::Buffer staging;
    u32 width, height;
    u32 row_texels;     // buffer row length in texels (pitch)
    bool block;
    bool storage;       // written by the shader: keep in GENERAL layout
};

struct ImageWriteBack {
    vk::Image img;
    const Buffer* staging;
    void* guest;
    size_t bytes;
    u32 width, height, row_texels;
    bool block;
    std::shared_ptr<const Tiler> tiler{}; // tiled guest image: tile back on write
    u32 row_elems{}, rows{};
};

struct BufferWriteBack {
    const Buffer* buf;
    void* guest;
    size_t size;
};

struct Bound {
    std::vector<vk::DescriptorSetLayoutBinding> layout;
    std::vector<vk::WriteDescriptorSet> writes;
    std::vector<std::unique_ptr<vk::DescriptorBufferInfo>> binfos;
    std::vector<std::unique_ptr<vk::DescriptorImageInfo>> iinfos;
    std::vector<PendingUpload> uploads;
    std::vector<ImageWriteBack> image_writebacks;
    std::vector<BufferWriteBack> buffer_writebacks;
    u32 binding = 0;
};

vk::ShaderStageFlagBits StageBit(Shader::Stage s) {
    switch (s) {
    case Shader::Stage::Fragment: return vk::ShaderStageFlagBits::eFragment;
    case Shader::Stage::Compute: return vk::ShaderStageFlagBits::eCompute;
    default: return vk::ShaderStageFlagBits::eVertex;
    }
}

vk::BufferImageCopy CopyRegion(u32 w, u32 h, u32 row_texels, bool block) {
    return {.bufferOffset = 0,
            .bufferRowLength = block ? ((row_texels + 3) / 4) * 4 : row_texels,
            .bufferImageHeight = 0,
            .imageSubresource = {vk::ImageAspectFlagBits::eColor, 0, 0, 1},
            .imageOffset = {0, 0, 0},
            .imageExtent = {w, h, 1}};
}

// Create descriptors for everything one translated stage references, in the
// order shadPS4's descriptor-set layout uses: buffers, images, samplers.
void BindStage(Frame& fr, const TranslatedShader& ts, Bound& bd) {
    const auto& info = *ts.info;
    const auto stage_bit = StageBit(info.stage);

    for (const auto& br : info.buffers) {
        bd.layout.push_back({.binding = bd.binding,
                             .descriptorType = vk::DescriptorType::eStorageBuffer,
                             .descriptorCount = 1,
                             .stageFlags = stage_bit});
        Buffer* b = nullptr;
        switch (br.buffer_type) {
        case Shader::BufferType::Flatbuf: {
            const size_t n = info.flattened_ud_buf.size() * 4;
            b = &fr.NewBuffer(n, vk::BufferUsageFlagBits::eStorageBuffer);
            std::memcpy(b->map, info.flattened_ud_buf.data(), n);
            break;
        }
        case Shader::BufferType::Guest: {
            const auto sharp = br.GetSharp(info);
            const size_t n = sharp.GetSize();
            b = &fr.NewBuffer(n, vk::BufferUsageFlagBits::eStorageBuffer);
            void* guest = reinterpret_cast<void*>(uintptr_t(sharp.base_address));
            if (n && guest) {
                std::memcpy(b->map, guest, n);
                if (br.is_written) {
                    bd.buffer_writebacks.push_back({b, guest, n});
                }
            }
            break;
        }
        case Shader::BufferType::GdsBuffer:
        case Shader::BufferType::SharedMemory:
            b = &fr.NewBuffer(64_KB, vk::BufferUsageFlagBits::eStorageBuffer);
            break;
        default:
            Fail(fmt::format("buffer type {} needs direct memory access, not supported",
                             u32(br.buffer_type)));
        }
        auto bi = std::make_unique<vk::DescriptorBufferInfo>(
            vk::DescriptorBufferInfo{.buffer = b->buf, .offset = 0, .range = VK_WHOLE_SIZE});
        bd.writes.push_back({.dstBinding = bd.binding,
                             .descriptorCount = 1,
                             .descriptorType = vk::DescriptorType::eStorageBuffer,
                             .pBufferInfo = bi.get()});
        bd.binfos.push_back(std::move(bi));
        ++bd.binding;
    }

    for (const auto& ir : info.images) {
        const auto sharp = ir.GetSharp(info);
        if (ir.mip_fallback_mode == Shader::MipStorageFallbackMode::DynamicIndex) {
            Fail("dynamically indexed mip levels not supported yet");
        }
        const auto dtype = ir.is_written ? vk::DescriptorType::eStorageImage
                                         : vk::DescriptorType::eSampledImage;
        bd.layout.push_back(
            {.binding = bd.binding, .descriptorType = dtype, .descriptorCount = 1,
             .stageFlags = stage_bit});
        const auto view_type = sharp.GetViewType(ir.is_array);
        const bool is_1d = view_type == AmdGpu::ImageType::Color1D;
        if (view_type != AmdGpu::ImageType::Color2D && !is_1d) {
            const u32* d = reinterpret_cast<const u32*>(&sharp);
            Fail(fmt::format("image type {} not supported yet [T# {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}]",
                             AmdGpu::NameOf(view_type), d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]));
        }
        const auto fi = MapFormat(sharp.GetDataFmt(), sharp.GetNumberFmt());
        if (!fi) {
            Fail(fmt::format("texture format {}/{} not mapped yet", u32(sharp.GetDataFmt()),
                             u32(sharp.GetNumberFmt())));
        }
        const u32 w = u32(sharp.width) + 1, h = is_1d ? 1u : u32(sharp.height) + 1;
        const u32 pitch = u32(sharp.pitch) + 1;
        auto usage = vk::ImageUsageFlagBits::eSampled | vk::ImageUsageFlagBits::eTransferDst;
        if (ir.is_written) {
            usage |= vk::ImageUsageFlagBits::eStorage | vk::ImageUsageFlagBits::eTransferSrc;
        }
        Image& im = fr.NewImage({.imageType = is_1d ? vk::ImageType::e1D : vk::ImageType::e2D,
                                 .format = fi->fmt,
                                 .extent = {w, is_1d ? 1u : h, 1},
                                 .mipLevels = 1,
                                 .arrayLayers = 1,
                                 .samples = vk::SampleCountFlagBits::e1,
                                 .tiling = vk::ImageTiling::eOptimal,
                                 .usage = usage,
                                 .initialLayout = vk::ImageLayout::eUndefined});
        const auto sw = sharp.DstSelect();
        im.view = fr.dev.createImageView(
            {.image = im.img,
             .viewType = is_1d ? vk::ImageViewType::e1D : vk::ImageViewType::e2D,
             .format = fi->fmt,
             .components = ir.is_written
                               ? vk::ComponentMapping{}
                               : vk::ComponentMapping{MapSwizzle(sw.r), MapSwizzle(sw.g),
                                                      MapSwizzle(sw.b), MapSwizzle(sw.a)},
             .subresourceRange = {vk::ImageAspectFlagBits::eColor, 0, 1, 0, 1}});
        // stage the texels (linear, pitch-aligned rows)
        const u32 rows = fi->block ? (h + 3) / 4 : h;
        const u32 row_elems = fi->block ? (pitch + 3) / 4 : pitch;
        const size_t bytes = size_t(rows) * row_elems * fi->bytes;
        Buffer& st = fr.NewBuffer(bytes, vk::BufferUsageFlagBits::eTransferSrc |
                                             vk::BufferUsageFlagBits::eTransferDst);
        void* src = reinterpret_cast<void*>(uintptr_t(sharp.base_address) << 8);
        if (!src) {
            Fail("texture base address is null");
        }
        // Tiled textures are detiled into the linear staging rows (block
        // formats tile whole 4x4 blocks, so they use block units here).
        const auto mode = AmdGpu::TileMode(u32(sharp.tiling_index));
        std::shared_ptr<const Tiler> tiler;
        if (!IsLinear(mode)) {
            std::string why;
            tiler = Tiler::Get(mode, fi->bytes, row_elems, rows, &why);
            if (!tiler) {
                Fail(fmt::format("texture tile mode {}: {}", u32(mode), why));
            }
            tiler->Detile(static_cast<const u8*>(src), static_cast<u8*>(st.map), row_elems,
                          rows, row_elems);
        } else {
            std::memcpy(st.map, src, bytes);
        }
        bd.uploads.push_back({im.img, st.buf, w, h, pitch, fi->block, ir.is_written});
        if (ir.is_written) {
            bd.image_writebacks.push_back(
                {im.img, &st, src, bytes, w, h, pitch, fi->block, tiler, row_elems, rows});
        }

        auto ii = std::make_unique<vk::DescriptorImageInfo>(vk::DescriptorImageInfo{
            .imageView = im.view,
            .imageLayout = ir.is_written ? vk::ImageLayout::eGeneral
                                         : vk::ImageLayout::eShaderReadOnlyOptimal});
        bd.writes.push_back({.dstBinding = bd.binding,
                             .descriptorCount = 1,
                             .descriptorType = dtype,
                             .pImageInfo = ii.get()});
        bd.iinfos.push_back(std::move(ii));
        ++bd.binding;
    }

    for (const auto& sr : info.samplers) {
        const auto s = sr.GetSharp(info);
        bd.layout.push_back({.binding = bd.binding,
                             .descriptorType = vk::DescriptorType::eSampler,
                             .descriptorCount = 1,
                             .stageFlags = stage_bit});
        const auto filt = [](AmdGpu::Filter f) {
            return (f == AmdGpu::Filter::Bilinear || f == AmdGpu::Filter::AnisoLinear)
                       ? vk::Filter::eLinear
                       : vk::Filter::eNearest;
        };
        const bool unnorm = s.force_unnormalized.Value() != 0;
        vk::SamplerCreateInfo ci{
            .magFilter = filt(s.xy_mag_filter),
            .minFilter = filt(s.xy_min_filter),
            .mipmapMode = s.mip_filter == AmdGpu::MipFilter::Linear
                              ? vk::SamplerMipmapMode::eLinear
                              : vk::SamplerMipmapMode::eNearest,
            .addressModeU = unnorm ? vk::SamplerAddressMode::eClampToEdge : MapClamp(s.clamp_x),
            .addressModeV = unnorm ? vk::SamplerAddressMode::eClampToEdge : MapClamp(s.clamp_y),
            .addressModeW = unnorm ? vk::SamplerAddressMode::eClampToEdge : MapClamp(s.clamp_z),
            .mipLodBias = 0.0f,
            .anisotropyEnable = VK_FALSE,
            .maxAnisotropy = 1.0f,
            .compareEnable = VK_FALSE,
            .minLod = 0.0f,
            .maxLod = unnorm ? 0.0f : float(s.max_lod.Value()) / 256.0f,
            .borderColor = vk::BorderColor::eFloatTransparentBlack,
            .unnormalizedCoordinates = unnorm,
        };
        if (unnorm) {
            ci.minFilter = ci.magFilter;
        }
        const auto smp = fr.dev.createSampler(ci);
        fr.samplers.push_back(smp);
        auto ii =
            std::make_unique<vk::DescriptorImageInfo>(vk::DescriptorImageInfo{.sampler = smp});
        bd.writes.push_back({.dstBinding = bd.binding,
                             .descriptorCount = 1,
                             .descriptorType = vk::DescriptorType::eSampler,
                             .pImageInfo = ii.get()});
        bd.iinfos.push_back(std::move(ii));
        ++bd.binding;
    }
}

// Create the set layout, pipeline layout and a filled descriptor set.
vk::DescriptorSet MakeSet(Frame& fr, Bound& bd, vk::ShaderStageFlags push_stages) {
    const auto& dev = fr.dev;
    fr.set_layout = dev.createDescriptorSetLayout(
        {.bindingCount = u32(bd.layout.size()), .pBindings = bd.layout.data()});
    const vk::PushConstantRange pcr{.stageFlags = push_stages,
                                    .offset = 0,
                                    .size = sizeof(Shader::PushData)};
    fr.pipe_layout = dev.createPipelineLayout({.setLayoutCount = 1,
                                               .pSetLayouts = &fr.set_layout,
                                               .pushConstantRangeCount = 1,
                                               .pPushConstantRanges = &pcr});
    const std::array<vk::DescriptorPoolSize, 4> sizes = {{
        {vk::DescriptorType::eStorageBuffer, 64},
        {vk::DescriptorType::eSampledImage, 64},
        {vk::DescriptorType::eStorageImage, 16},
        {vk::DescriptorType::eSampler, 32},
    }};
    fr.pool = dev.createDescriptorPool(
        {.maxSets = 1, .poolSizeCount = u32(sizes.size()), .pPoolSizes = sizes.data()});
    const auto set = dev.allocateDescriptorSets(
        {.descriptorPool = fr.pool, .descriptorSetCount = 1, .pSetLayouts = &fr.set_layout})[0];
    for (auto& w : bd.writes) {
        w.dstSet = set;
    }
    if (!bd.writes.empty()) {
        dev.updateDescriptorSets(bd.writes, {});
    }
    return set;
}

using S2 = vk::PipelineStageFlagBits2;
using A2 = vk::AccessFlagBits2;
using L = vk::ImageLayout;

void Barrier(vk::CommandBuffer c, vk::Image img, L from, L to, vk::PipelineStageFlags2 src_stage,
             vk::AccessFlags2 src_access, vk::PipelineStageFlags2 dst_stage,
             vk::AccessFlags2 dst_access,
             vk::ImageAspectFlags aspect = vk::ImageAspectFlagBits::eColor) {
    const vk::ImageMemoryBarrier2 b{.srcStageMask = src_stage,
                                    .srcAccessMask = src_access,
                                    .dstStageMask = dst_stage,
                                    .dstAccessMask = dst_access,
                                    .oldLayout = from,
                                    .newLayout = to,
                                    .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                                    .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                                    .image = img,
                                    .subresourceRange = {aspect, 0, 1, 0, 1}};
    c.pipelineBarrier2({.imageMemoryBarrierCount = 1, .pImageMemoryBarriers = &b});
}

void RecordUploads(vk::CommandBuffer c, const Bound& bd) {
    for (const auto& up : bd.uploads) {
        Barrier(c, up.img, L::eUndefined, L::eTransferDstOptimal, S2::eTopOfPipe, {}, S2::eCopy,
                A2::eTransferWrite);
        c.copyBufferToImage(up.staging, up.img, L::eTransferDstOptimal,
                            CopyRegion(up.width, up.height, up.row_texels, up.block));
        Barrier(c, up.img, L::eTransferDstOptimal,
                up.storage ? L::eGeneral : L::eShaderReadOnlyOptimal, S2::eCopy,
                A2::eTransferWrite, S2::eAllCommands, A2::eShaderRead | A2::eShaderWrite);
    }
}

void RecordImageWriteBacks(vk::CommandBuffer c, const Bound& bd) {
    for (const auto& wb : bd.image_writebacks) {
        Barrier(c, wb.img, L::eGeneral, L::eGeneral, S2::eAllCommands, A2::eShaderWrite,
                S2::eCopy, A2::eTransferRead);
        c.copyImageToBuffer(wb.img, L::eGeneral, wb.staging->buf,
                            CopyRegion(wb.width, wb.height, wb.row_texels, wb.block));
    }
}

void RecordHostBarrier(vk::CommandBuffer c) {
    const vk::MemoryBarrier2 host{.srcStageMask = S2::eAllCommands,
                                  .srcAccessMask = A2::eMemoryWrite,
                                  .dstStageMask = S2::eHost,
                                  .dstAccessMask = A2::eHostRead};
    c.pipelineBarrier2({.memoryBarrierCount = 1, .pMemoryBarriers = &host});
}

void SubmitAndWait(Frame& fr) {
    Device& D = Dev();
    fr.fence = D.dev.createFence({});
    const vk::SubmitInfo si{.commandBufferCount = 1, .pCommandBuffers = &fr.cmd};
    D.queue.submit(si, fr.fence);
    if (D.dev.waitForFences(fr.fence, VK_TRUE, 10'000'000'000ull) != vk::Result::eSuccess) {
        Fail("GPU timed out (shader hang?)");
    }
}

void FinishWriteBacks(const Bound& bd) {
    for (const auto& wb : bd.buffer_writebacks) {
        std::memcpy(wb.guest, wb.buf->map, wb.size);
    }
    for (const auto& wb : bd.image_writebacks) {
        if (wb.tiler) {
            wb.tiler->Tile(static_cast<const u8*>(wb.staging->map), static_cast<u8*>(wb.guest),
                           wb.row_elems, wb.rows, wb.row_elems);
        } else {
            std::memcpy(wb.guest, wb.staging->map, wb.bytes);
        }
    }
}

vk::CommandBuffer BeginCmd(Frame& fr) {
    Device& D = Dev();
    fr.cmd = D.dev.allocateCommandBuffers({.commandPool = D.cmd_pool,
                                           .level = vk::CommandBufferLevel::ePrimary,
                                           .commandBufferCount = 1})[0];
    fr.cmd.begin({.flags = vk::CommandBufferUsageFlagBits::eOneTimeSubmit});
    return fr.cmd;
}

// Per-phase wall time of graphics jobs (ms), for gnm_profile().
enum ProfPhase { kTranslate, kBind, kTargets, kPipeline, kRecord, kGpu, kWriteBack, kNumPhases };
constexpr const char* kPhaseNames[kNumPhases] = {"translate", "bind",  "targets", "pipeline",
                                                 "record",    "gpu",   "writeback"};
double g_prof_ms[kNumPhases]{};
u32 g_prof_draws = 0;

struct PhaseTimer {
    std::chrono::steady_clock::time_point t = std::chrono::steady_clock::now();
    void Lap(ProfPhase p) {
        const auto now = std::chrono::steady_clock::now();
        g_prof_ms[p] += std::chrono::duration<double, std::milli>(now - t).count();
        t = now;
    }
};

// -------------------------------------------------------------- draw batching
//
// Consecutive graphics draws of one gnm_submit() are recorded into a single
// command buffer and executed with one queue submit + fence wait, instead of
// one submit per draw. Each draw's Vulkan resources (pipeline, descriptor
// pool, staging buffers, ...) live in its own heap Frame, retained in the
// batch until the fence signals so they outlive recording; CPU-side work that
// needs the GPU result (write-backs to guest memory, read-backs) is deferred
// to the flush. Resident render targets already persist on the GPU across a
// submit's draws, so nothing round-trips through guest memory between them.
//
// The batch is flushed - everything so far submitted and waited on - exactly
// when a later operation needs those draws' results in memory: before a
// resident surface is written back (FlushRange/WriteBack), after a draw that
// writes guest memory through a UAV, before a compute dispatch, and at submit
// end (ReleaseSurfaces). This keeps guest memory identical to the per-draw
// path; only when no such hazard occurs do draws actually batch.
struct Readback {
    const Buffer* staging;   // points into a retained Frame's buffer deque
    void* dst;
    size_t bytes;
};

struct Batch {
    vk::CommandBuffer cmd;
    bool open = false;                                 // cmd buffer begun, >=1 draw recorded
    std::vector<std::unique_ptr<Frame>> frames;        // resources kept alive until the wait
    std::vector<Bound> writebacks;                     // shader UAV writes -> guest, after wait
    std::vector<Readback> readbacks;                   // colour target read-backs, after wait
};
Batch g_batch;

// Ensure the batch command buffer is open and return it (draws record into it).
vk::CommandBuffer BeginBatch() {
    Device& D = Dev();
    if (!g_batch.open) {
        g_batch.cmd = D.dev.allocateCommandBuffers({.commandPool = D.cmd_pool,
                                                    .level = vk::CommandBufferLevel::ePrimary,
                                                    .commandBufferCount = 1})[0];
        g_batch.cmd.begin({.flags = vk::CommandBufferUsageFlagBits::eOneTimeSubmit});
        g_batch.open = true;
    }
    return g_batch.cmd;
}

// Submit and wait on every draw recorded so far, run their deferred CPU
// copies, then drop the retained resources. A no-op when nothing is pending.
u32 g_flush_count = 0;
void FlushBatch() {
    if (!g_batch.open) {
        return;
    }
    ++g_flush_count;
    Device& D = Dev();
    g_batch.cmd.end();
    const auto t0 = std::chrono::steady_clock::now();
    vk::Fence fence = D.dev.createFence({});
    const vk::SubmitInfo si{.commandBufferCount = 1, .pCommandBuffers = &g_batch.cmd};
    D.queue.submit(si, fence);
    if (D.dev.waitForFences(fence, VK_TRUE, 10'000'000'000ull) != vk::Result::eSuccess) {
        D.dev.destroyFence(fence);
        D.dev.freeCommandBuffers(D.cmd_pool, g_batch.cmd);
        g_batch.open = false;
        Fail("GPU timed out (shader hang?)");
    }
    const auto t1 = std::chrono::steady_clock::now();
    g_prof_ms[kGpu] += std::chrono::duration<double, std::milli>(t1 - t0).count();

    for (const auto& rb : g_batch.readbacks) {
        std::memcpy(rb.dst, rb.staging->map, rb.bytes);
    }
    for (const auto& bd : g_batch.writebacks) {
        FinishWriteBacks(bd);
    }
    g_prof_ms[kWriteBack] +=
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t1).count();

    D.dev.destroyFence(fence);
    D.dev.freeCommandBuffers(D.cmd_pool, g_batch.cmd);
    g_batch.readbacks.clear();
    g_batch.writebacks.clear();
    g_batch.frames.clear();   // ~Frame frees each draw's resources and resets the memory pool
    g_batch.open = false;
}

// ------------------------------------------------------------- resident targets
//
// A guest render target stays on the GPU between the draws of one
// gnm_submit(): only the first draw detiles/uploads it and it is written
// back (retiled) once - at the end of the submit, or earlier when a draw or
// dispatch reads/writes overlapping memory or a CP packet (DMA_DATA /
// WRITE_DATA) touches it. Nothing else can change guest memory during a
// submit, so this is exact; between submits the CPU runs, so surfaces are
// always written back and dropped at the end of each submit.
struct Surface {
    u64 address{};
    size_t footprint{};          // guest bytes [address, address + footprint)
    u32 width{}, height{}, row{};
    FormatInfo fi{};
    AmdGpu::TileMode mode{};
    std::shared_ptr<const Tiler> tiler;
    Image img{};
    bool dirty{};

    bool Overlaps(u64 lo, u64 hi) const {
        return lo < address + footprint && address < hi;
    }
    ~Surface() {
        auto dev = Dev().dev;
        if (img.view) dev.destroyImageView(img.view);
        if (img.img) dev.destroyImage(img.img);
        if (img.mem) dev.freeMemory(img.mem);
    }
};

std::vector<std::unique_ptr<Surface>> g_surfaces;
u32 g_surface_writebacks = 0;

void WriteBack(Surface& s) {
    if (!s.dirty) {
        return;
    }
    // Pending batched draws may have rendered into this surface's image; make
    // sure they have executed before we read it back.
    FlushBatch();
    Device& D = Dev();
    Frame fr{.dev = D.dev};
    const size_t bytes = size_t(s.row) * s.height * s.fi.bytes;
    Buffer& st = fr.NewBuffer(bytes, vk::BufferUsageFlagBits::eTransferDst);
    auto c = BeginCmd(fr);
    Barrier(c, s.img.img, L::eColorAttachmentOptimal, L::eTransferSrcOptimal,
            S2::eColorAttachmentOutput, A2::eColorAttachmentWrite, S2::eCopy, A2::eTransferRead);
    c.copyImageToBuffer(s.img.img, L::eTransferSrcOptimal, st.buf,
                        CopyRegion(s.width, s.height, s.row, false));
    Barrier(c, s.img.img, L::eTransferSrcOptimal, L::eColorAttachmentOptimal, S2::eCopy,
            A2::eTransferRead, S2::eColorAttachmentOutput,
            A2::eColorAttachmentRead | A2::eColorAttachmentWrite);
    RecordHostBarrier(c);
    c.end();
    SubmitAndWait(fr);
    auto* dst = reinterpret_cast<u8*>(uintptr_t(s.address));
    if (s.tiler) {
        s.tiler->Tile(static_cast<const u8*>(st.map), dst, s.width, s.height, s.row);
    } else {
        std::memcpy(dst, st.map, bytes);
    }
    s.dirty = false;
    ++g_surface_writebacks;
}

// A resident depth/stencil target: one Vulkan image with the guest's Z and
// stencil planes (separate tiled surfaces in guest memory, like DB_Z_* and
// DB_STENCIL_*). Same lifetime rules as Surface.
struct DepthSurface {
    u64 z_address{}, s_address{};
    size_t z_footprint{}, s_footprint{};
    u32 width{}, height{}, z_bits{};
    AmdGpu::TileMode mode{};
    vk::Format fmt{};
    bool has_z{}, has_s{};
    std::shared_ptr<const Tiler> z_tiler, s_tiler; // null = linear plane
    Image img{};
    bool dirty{};

    bool Overlaps(u64 lo, u64 hi) const {
        return (has_z && lo < z_address + z_footprint && z_address < hi) ||
               (has_s && lo < s_address + s_footprint && s_address < hi);
    }
    bool CombinedFormat() const {
        return fmt == vk::Format::eD32SfloatS8Uint || fmt == vk::Format::eD16UnormS8Uint;
    }
    bool Depth16() const { // depth aspect is 16-bit unorm in the image
        return fmt == vk::Format::eD16Unorm || fmt == vk::Format::eD16UnormS8Uint;
    }
    vk::ImageAspectFlags Aspects() const {
        return CombinedFormat()
                   ? vk::ImageAspectFlagBits::eDepth | vk::ImageAspectFlagBits::eStencil
                   : vk::ImageAspectFlags(vk::ImageAspectFlagBits::eDepth);
    }
    size_t ZBytes() const { // staging bytes of the depth aspect (image format)
        return size_t(width) * height * (Depth16() ? 2 : 4);
    }
    size_t SBytes() const {
        return CombinedFormat() ? size_t(width) * height : 0;
    }
    std::vector<vk::BufferImageCopy> Copies() const {
        std::vector<vk::BufferImageCopy> r;
        r.push_back({.bufferOffset = 0,
                     .imageSubresource = {vk::ImageAspectFlagBits::eDepth, 0, 0, 1},
                     .imageExtent = {width, height, 1}});
        if (CombinedFormat()) {
            r.push_back({.bufferOffset = ZBytes(),
                         .imageSubresource = {vk::ImageAspectFlagBits::eStencil, 0, 0, 1},
                         .imageExtent = {width, height, 1}});
        }
        return r;
    }
    ~DepthSurface() {
        auto dev = Dev().dev;
        if (img.view) dev.destroyImageView(img.view);
        if (img.img) dev.destroyImage(img.img);
        if (img.mem) dev.freeMemory(img.mem);
    }
};

std::vector<std::unique_ptr<DepthSurface>> g_depth_surfaces;

// One guest plane <-> tight linear rows.
void PlaneIn(const std::shared_ptr<const Tiler>& t, const u8* guest, u8* lin, u32 w, u32 h,
             u32 bpp) {
    if (t) {
        t->Detile(guest, lin, w, h, w);
    } else {
        std::memcpy(lin, guest, size_t(w) * h * bpp);
    }
}
void PlaneOut(const std::shared_ptr<const Tiler>& t, const u8* lin, u8* guest, u32 w, u32 h,
              u32 bpp) {
    if (t) {
        t->Tile(lin, guest, w, h, w);
    } else {
        std::memcpy(guest, lin, size_t(w) * h * bpp);
    }
}

// guest planes -> staging laid out as Copies() expects
void FillDepthStaging(const DepthSurface& s, u8* st) {
    const size_t n = size_t(s.width) * s.height;
    if (s.has_z) {
        const auto* gz = reinterpret_cast<const u8*>(uintptr_t(s.z_address));
        if (s.z_bits == 16 && !s.Depth16()) { // Z16 in a D32S8 image
            std::vector<u16> z16(n);
            PlaneIn(s.z_tiler, gz, reinterpret_cast<u8*>(z16.data()), s.width, s.height, 2);
            auto* f = reinterpret_cast<float*>(st);
            for (size_t i = 0; i < n; ++i) {
                f[i] = float(z16[i]) / 65535.0f;
            }
        } else {
            PlaneIn(s.z_tiler, gz, st, s.width, s.height, s.z_bits / 8);
        }
    } else if (!s.Depth16()) {
        std::fill_n(reinterpret_cast<float*>(st), n, 1.0f);
    }
    if (s.has_s) {
        PlaneIn(s.s_tiler, reinterpret_cast<const u8*>(uintptr_t(s.s_address)), st + s.ZBytes(),
                s.width, s.height, 1);
    }
}

void StoreDepthStaging(const DepthSurface& s, const u8* st) {
    const size_t n = size_t(s.width) * s.height;
    if (s.has_z) {
        auto* gz = reinterpret_cast<u8*>(uintptr_t(s.z_address));
        if (s.z_bits == 16 && !s.Depth16()) {
            std::vector<u16> z16(n);
            const auto* f = reinterpret_cast<const float*>(st);
            for (size_t i = 0; i < n; ++i) {
                z16[i] = u16(std::lround(std::clamp(f[i], 0.0f, 1.0f) * 65535.0f));
            }
            PlaneOut(s.z_tiler, reinterpret_cast<const u8*>(z16.data()), gz, s.width, s.height,
                     2);
        } else {
            PlaneOut(s.z_tiler, st, gz, s.width, s.height, s.z_bits / 8);
        }
    }
    if (s.has_s) {
        PlaneOut(s.s_tiler, st + s.ZBytes(), reinterpret_cast<u8*>(uintptr_t(s.s_address)),
                 s.width, s.height, 1);
    }
}

constexpr auto kDepthStages =
    vk::PipelineStageFlagBits2::eEarlyFragmentTests | vk::PipelineStageFlagBits2::eLateFragmentTests;
constexpr auto kDepthAccess = vk::AccessFlagBits2::eDepthStencilAttachmentRead |
                              vk::AccessFlagBits2::eDepthStencilAttachmentWrite;

void WriteBack(DepthSurface& s) {
    if (!s.dirty) {
        return;
    }
    // Pending batched draws may have written this depth image; flush them first.
    FlushBatch();
    Device& D = Dev();
    Frame fr{.dev = D.dev};
    Buffer& st = fr.NewBuffer(s.ZBytes() + s.SBytes(), vk::BufferUsageFlagBits::eTransferDst);
    auto c = BeginCmd(fr);
    Barrier(c, s.img.img, L::eDepthStencilAttachmentOptimal, L::eTransferSrcOptimal,
            kDepthStages, A2::eDepthStencilAttachmentWrite, S2::eCopy, A2::eTransferRead,
            s.Aspects());
    c.copyImageToBuffer(s.img.img, L::eTransferSrcOptimal, st.buf, s.Copies());
    Barrier(c, s.img.img, L::eTransferSrcOptimal, L::eDepthStencilAttachmentOptimal, S2::eCopy,
            A2::eTransferRead, kDepthStages, kDepthAccess, s.Aspects());
    RecordHostBarrier(c);
    c.end();
    SubmitAndWait(fr);
    StoreDepthStaging(s, static_cast<const u8*>(st.map));
    s.dirty = false;
    ++g_surface_writebacks;
}

struct TargetRes {
    const ColorTarget* t;
    Image* img;
    Buffer* staging;     // linear copy of the guest surface (address != 0) or readback
    FormatInfo fi;
    size_t bytes;
    u32 row_texels;
    std::shared_ptr<const Tiler> tiler; // tiled guest surface: detile on load, tile on store
    Surface* surf{};     // resident guest target (no per-draw readback)
    bool upload{};       // surface is new this draw: fill it from guest memory first
};

// Write back (and drop) every resident surface overlapping a guest range the
// current job is about to read or write through some other path.
void FlushRange(u64 lo, u64 hi) {
    for (size_t i = 0; i < g_surfaces.size();) {
        if (g_surfaces[i]->Overlaps(lo, hi)) {
            WriteBack(*g_surfaces[i]);
            g_surfaces.erase(g_surfaces.begin() + i);
        } else {
            ++i;
        }
    }
    for (size_t i = 0; i < g_depth_surfaces.size();) {
        if (g_depth_surfaces[i]->Overlaps(lo, hi)) {
            WriteBack(*g_depth_surfaces[i]);
            g_depth_surfaces.erase(g_depth_surfaces.begin() + i);
        } else {
            ++i;
        }
    }
}

// Guest memory a translated stage will access through descriptors.
void FlushForShader(const TranslatedShader& ts) {
    if (g_surfaces.empty() && g_depth_surfaces.empty()) {
        return;
    }
    // debug: PSEMU_GNM_FLUSH_ALL=1 writes back + drops every resident surface
    // before each draw/dispatch (exercises the write-back/reload path)
    static const bool flush_all = [] {
        const char* v = std::getenv("PSEMU_GNM_FLUSH_ALL");
        return v && *v == '1';
    }();
    if (flush_all) {
        FlushRange(0, ~0ull);
        return;
    }
    const auto& info = *ts.info;
    for (const auto& br : info.buffers) {
        if (br.buffer_type == Shader::BufferType::Guest) {
            const auto sharp = br.GetSharp(info);
            const u64 a = sharp.base_address;
            FlushRange(a, a + std::max<size_t>(sharp.GetSize(), 1));
        }
    }
    for (const auto& ir : info.images) {
        const auto sharp = ir.GetSharp(info);
        const u64 a = u64(sharp.base_address) << 8;
        // the image's real footprint (format, pitch, tiling); unknown formats
        // fall back to a generous 16 bytes per texel
        const auto fi = MapFormat(sharp.GetDataFmt(), sharp.GetNumberFmt());
        const u32 pitch = u32(sharp.pitch) + 1, height = u32(sharp.height) + 1;
        const u32 rows = fi && fi->block ? (height + 3) / 4 : height;
        const u32 elems = fi && fi->block ? (pitch + 3) / 4 : pitch;
        const u32 bpe = fi ? fi->bytes : 16;
        u64 n = u64(rows) * elems * bpe;
        const auto mode = AmdGpu::TileMode(u32(sharp.tiling_index));
        if (fi && !IsLinear(mode)) {
            if (const auto t = Tiler::Get(mode, bpe, elems, rows, nullptr)) {
                n = t->TiledBytes();
            }
        }
        FlushRange(a, a + std::max<u64>(n, 1));
    }
}

} // namespace

void ExecuteGraphics(const GraphicsJob& job) {
    Device& D = Dev();
    // A depth-only draw may have no pixel shader (job.ps.code == nullptr).
    const bool has_ps = job.ps.code != nullptr;
    if (job.vs.stage != GNM_STAGE_VS || (has_ps && job.ps.stage != GNM_STAGE_PS)) {
        Fail("a graphics job needs a VS (and a PS unless depth-only)");
    }
    if (job.targets.empty() && !job.depth) {
        Fail("no colour or depth target bound");
    }
    if (!has_ps && !job.targets.empty()) {
        Fail("colour targets bound but no pixel shader");
    }
    PhaseTimer pt;
    ++g_prof_draws;

    // Translate in shadPS4's order: fragment first, then vertex (shared numbering).
    Shader::Backend::Bindings bnd{};
    const auto ps = has_ps ? Translate(job.ps, D.profile, bnd, &job.ps_extras) : nullptr;
    const auto vs = Translate(job.vs, D.profile, bnd, &job.vs_extras);
    pt.Lap(kTranslate);
    if (ps) {
        FlushForShader(*ps); // resident targets the shaders read as textures/buffers
    }
    FlushForShader(*vs);
    // This draw's resources live in their own heap Frame, retained in the batch
    // until its fence signals (BeginBatch/FlushBatch), so they outlive recording.
    auto frp = std::make_unique<Frame>(Frame{.dev = D.dev});
    Frame& fr = *frp;

    // ---- vertex attributes (fetch shader): one binding per attribute, the
    // guest V# buffer copied into a vertex buffer, location = semantic.
    std::vector<vk::VertexInputAttributeDescription> vattrs;
    std::vector<vk::VertexInputBindingDescription> vbinds;
    std::vector<vk::Buffer> vbufs;
    u32 first_vertex = 0, first_instance = 0;
    if (vs->info->has_fetch_shader) {
        const auto fsd = Shader::Gcn::ParseFetchShader(*vs->info);
        if (!fsd) {
            Fail("vertex shader's fetch shader could not be parsed");
        }
        using Step = Shader::Gcn::VertexAttribute::InstanceIdType;
        for (const auto& attrib : fsd->attributes) {
            const auto sharp = attrib.GetSharp(*vs->info);
            const auto vfmt = VertexFormat(sharp.GetDataFmt(), sharp.GetNumberFmt());
            if (!vfmt) {
                Fail(fmt::format("vertex attribute {} format {}/{} not mapped yet",
                                 attrib.semantic, u32(sharp.GetDataFmt()),
                                 u32(sharp.GetNumberFmt())));
            }
            const auto step = attrib.GetStepRate();
            if (step == Step::OverStepRate0 || step == Step::OverStepRate1) {
                Fail("instance step-rate divisors are not supported yet");
            }
            const size_t size = sharp.GetSize();
            const u32 binding = u32(vbinds.size());
            Buffer& vb = fr.NewBuffer(std::max<size_t>(size, 16),
                                      vk::BufferUsageFlagBits::eVertexBuffer);
            std::memset(vb.map, 0, std::max<size_t>(size, 16));
            if (size && sharp.base_address) {
                FlushRange(sharp.base_address, sharp.base_address + size);
                std::memcpy(vb.map, reinterpret_cast<const void*>(uintptr_t(sharp.base_address)),
                            size);
            }
            vattrs.push_back({.location = attrib.semantic,
                              .binding = binding,
                              .format = *vfmt,
                              .offset = 0});
            vbinds.push_back({.binding = binding,
                              .stride = u32(sharp.GetStride()),
                              .inputRate = step == Step::None ? vk::VertexInputRate::eVertex
                                                              : vk::VertexInputRate::eInstance});
            vbufs.push_back(vb.buf);
        }
        // VS user-data SGPRs that the fetch shader adds to the vertex/instance id
        if (fsd->vertex_offset_sgpr >= 0) {
            first_vertex = vs->info->user_data[fsd->vertex_offset_sgpr];
        }
        if (fsd->instance_offset_sgpr >= 0) {
            first_instance = vs->info->user_data[fsd->instance_offset_sgpr];
        }
    }
    Bound bd;
    if (ps) {
        BindStage(fr, *ps, bd);
    }
    BindStage(fr, *vs, bd);
    const auto set = MakeSet(fr, bd, vk::ShaderStageFlagBits::eAllGraphics);
    pt.Lap(kBind);

    // ---- colour targets (attachment index = MRT slot)
    u32 num_slots = 0;
    for (const auto& t : job.targets) {
        num_slots = std::max(num_slots, t.slot + 1);
    }
    std::vector<vk::Format> formats(num_slots, vk::Format::eUndefined);
    std::vector<vk::PipelineColorBlendAttachmentState> blends(num_slots);
    std::vector<TargetRes> res;
    std::vector<std::unique_ptr<Surface>> new_surfaces; // kept only if the draw succeeds
    for (const auto& t : job.targets) {
        if (t.slot >= 8 || t.width == 0 || t.height == 0 || t.width > 16384 ||
            t.height > 16384) {
            Fail("bad colour target");
        }
        const auto fi = MapFormat(t.dfmt, t.nfmt);
        if (!fi || fi->block) {
            Fail(fmt::format("render target format {}/{} not mapped yet", u32(t.dfmt),
                             u32(t.nfmt)));
        }
        std::shared_ptr<const Tiler> tiler;
        if (t.address && !IsLinear(t.tile_mode)) {
            std::string why;
            tiler = Tiler::Get(t.tile_mode, fi->bytes, t.pitch, t.height, &why);
            if (!tiler) {
                Fail(fmt::format("render target tile mode {}: {}", u32(t.tile_mode), why));
            }
        }
        formats[t.slot] = fi->fmt;
        const u32 row = t.address ? std::max(t.pitch, t.width) : t.width;
        const size_t bytes = size_t(row) * t.height * fi->bytes;
        if (t.address) {
            // resident guest target: reuse it, or create it (filled this draw)
            const size_t footprint = tiler ? tiler->TiledBytes() : bytes;
            Surface* s = nullptr;
            for (auto& g : g_surfaces) {
                if (g->address == t.address && g->width == t.width && g->height == t.height &&
                    g->row == row && g->fi.fmt == fi->fmt && g->mode == t.tile_mode) {
                    s = g.get();
                }
            }
            bool upload = false;
            if (!s) {
                FlushRange(t.address, t.address + footprint); // aliases of this memory
                auto ns = std::make_unique<Surface>();
                ns->address = t.address;
                ns->footprint = footprint;
                ns->width = t.width;
                ns->height = t.height;
                ns->row = row;
                ns->fi = *fi;
                ns->mode = t.tile_mode;
                ns->tiler = tiler;
                const vk::ImageCreateInfo ici{
                    .imageType = vk::ImageType::e2D,
                    .format = fi->fmt,
                    .extent = {t.width, t.height, 1},
                    .mipLevels = 1,
                    .arrayLayers = 1,
                    .samples = vk::SampleCountFlagBits::e1,
                    .tiling = vk::ImageTiling::eOptimal,
                    .usage = vk::ImageUsageFlagBits::eColorAttachment |
                             vk::ImageUsageFlagBits::eTransferSrc |
                             vk::ImageUsageFlagBits::eTransferDst,
                    .initialLayout = vk::ImageLayout::eUndefined};
                ns->img.img = D.dev.createImage(ici);
                const auto req = D.dev.getImageMemoryRequirements(ns->img.img);
                ns->img.mem = D.dev.allocateMemory(
                    {.allocationSize = req.size,
                     .memoryTypeIndex = FindMemory(req.memoryTypeBits,
                                                   vk::MemoryPropertyFlagBits::eDeviceLocal)});
                D.dev.bindImageMemory(ns->img.img, ns->img.mem, 0);
                ns->img.view = D.dev.createImageView(
                    {.image = ns->img.img,
                     .viewType = vk::ImageViewType::e2D,
                     .format = fi->fmt,
                     .subresourceRange = {vk::ImageAspectFlagBits::eColor, 0, 1, 0, 1}});
                s = ns.get();
                new_surfaces.push_back(std::move(ns));
                upload = true;
            }
            Buffer* st = nullptr;
            if (upload) {
                st = &fr.NewBuffer(bytes, vk::BufferUsageFlagBits::eTransferSrc);
                const auto* guest = reinterpret_cast<const u8*>(uintptr_t(t.address));
                if (tiler) {
                    tiler->Detile(guest, static_cast<u8*>(st->map), t.width, t.height, row);
                } else {
                    std::memcpy(st->map, guest, bytes);
                }
            }
            res.push_back({&t, &s->img, st, *fi, bytes, row, tiler, s, upload});
        }
        if (!t.address) {
        Image& im = fr.NewImage({.imageType = vk::ImageType::e2D,
                                 .format = fi->fmt,
                                 .extent = {t.width, t.height, 1},
                                 .mipLevels = 1,
                                 .arrayLayers = 1,
                                 .samples = vk::SampleCountFlagBits::e1,
                                 .tiling = vk::ImageTiling::eOptimal,
                                 .usage = vk::ImageUsageFlagBits::eColorAttachment |
                                          vk::ImageUsageFlagBits::eTransferSrc |
                                          vk::ImageUsageFlagBits::eTransferDst,
                                 .initialLayout = vk::ImageLayout::eUndefined});
        im.view = D.dev.createImageView({.image = im.img,
                                         .viewType = vk::ImageViewType::e2D,
                                         .format = fi->fmt,
                                         .subresourceRange = {vk::ImageAspectFlagBits::eColor,
                                                              0, 1, 0, 1}});
        // readback target (gnm_draw): rendered, then copied to t.readback
        Buffer& st = fr.NewBuffer(bytes, vk::BufferUsageFlagBits::eTransferSrc |
                                             vk::BufferUsageFlagBits::eTransferDst);
        res.push_back({&t, &im, &st, *fi, bytes, row, nullptr});
        }

        auto& b = blends[t.slot];
        b.colorWriteMask = vk::ColorComponentFlags(t.write_mask & 0xF);
        if (t.blend.enable) {
            const auto& bc = t.blend;
            b.blendEnable = VK_TRUE;
            b.srcColorBlendFactor = MapBlendFactor(bc.color_src_factor);
            b.dstColorBlendFactor = MapBlendFactor(bc.color_dst_factor);
            b.colorBlendOp = MapBlendOp(bc.color_func);
            if (bc.separate_alpha_blend) {
                b.srcAlphaBlendFactor = MapBlendFactor(bc.alpha_src_factor);
                b.dstAlphaBlendFactor = MapBlendFactor(bc.alpha_dst_factor);
                b.alphaBlendOp = MapBlendOp(bc.alpha_func);
            } else {
                b.srcAlphaBlendFactor = b.srcColorBlendFactor;
                b.dstAlphaBlendFactor = b.dstColorBlendFactor;
                b.alphaBlendOp = b.colorBlendOp;
            }
        }
    }
    // ---- depth / stencil target (resident like colour targets)
    DepthSurface* dsurf = nullptr;
    bool ds_upload = false;
    Buffer* ds_staging = nullptr;
    std::unique_ptr<DepthSurface> new_dsurf;
    bool ds_writes = false;
    vk::PipelineDepthStencilStateCreateInfo ds{};
    if (job.depth) {
        const auto& d = *job.depth;
        const bool has_z = d.z_address != 0, has_s = d.stencil_address != 0;
        if (d.width == 0 || d.height == 0 || d.width > 16384 || d.height > 16384) {
            Fail(fmt::format("bad depth target {}x{}", d.width, d.height));
        }
        const auto can_render = [&](vk::Format f) {
            return bool(D.phys.getFormatProperties(f).optimalTilingFeatures &
                        vk::FormatFeatureFlagBits::eDepthStencilAttachment);
        };
        // Z16+S8 natively when the GPU has D16S8 (exact 16-bit compares);
        // otherwise in D32S8, where reloaded Z16 values can differ from the
        // fragment's unquantised depth by < 1/65535 (equal-depth tests).
        vk::Format dfmt = !has_s           ? (d.z_bits == 16 ? vk::Format::eD16Unorm
                                                             : vk::Format::eD32Sfloat)
                          : d.z_bits == 16 && can_render(vk::Format::eD16UnormS8Uint)
                              ? vk::Format::eD16UnormS8Uint
                              : vk::Format::eD32SfloatS8Uint;
        const auto feats = D.phys.getFormatProperties(dfmt).optimalTilingFeatures;
        if (!(feats & vk::FormatFeatureFlagBits::eDepthStencilAttachment)) {
            Fail(fmt::format("GPU cannot render to {}", vk::to_string(dfmt)));
        }
        std::shared_ptr<const Tiler> zt, st;
        size_t zfoot = 0, sfoot = 0;
        std::string why;
        if (has_z) {
            if (!IsLinear(d.tile_mode)) {
                zt = Tiler::Get(d.tile_mode, d.z_bits / 8, d.width, d.height, &why);
                if (!zt) {
                    Fail(fmt::format("depth tile mode {}: {}", u32(d.tile_mode), why));
                }
            }
            zfoot = zt ? zt->TiledBytes() : size_t(d.width) * d.height * (d.z_bits / 8);
        }
        if (has_s) {
            if (!IsLinear(d.tile_mode)) {
                st = Tiler::Get(d.tile_mode, 1, d.width, d.height, &why);
                if (!st) {
                    Fail(fmt::format("stencil tile mode {}: {}", u32(d.tile_mode), why));
                }
            }
            sfoot = st ? st->TiledBytes() : size_t(d.width) * d.height;
        }
        for (auto& g : g_depth_surfaces) {
            if (g->z_address == d.z_address && g->s_address == d.stencil_address &&
                g->width == d.width && g->height == d.height && g->z_bits == d.z_bits &&
                g->mode == d.tile_mode && g->fmt == dfmt) {
                dsurf = g.get();
            }
        }
        if (!dsurf) {
            if (has_z) {
                FlushRange(d.z_address, d.z_address + zfoot);
            }
            if (has_s) {
                FlushRange(d.stencil_address, d.stencil_address + sfoot);
            }
            new_dsurf = std::make_unique<DepthSurface>();
            auto& s = *new_dsurf;
            s.z_address = d.z_address;
            s.s_address = d.stencil_address;
            s.z_footprint = zfoot;
            s.s_footprint = sfoot;
            s.width = d.width;
            s.height = d.height;
            s.z_bits = d.z_bits;
            s.mode = d.tile_mode;
            s.fmt = dfmt;
            s.has_z = has_z;
            s.has_s = has_s;
            s.z_tiler = zt;
            s.s_tiler = st;
            s.img.img = D.dev.createImage(
                {.imageType = vk::ImageType::e2D,
                 .format = dfmt,
                 .extent = {d.width, d.height, 1},
                 .mipLevels = 1,
                 .arrayLayers = 1,
                 .samples = vk::SampleCountFlagBits::e1,
                 .tiling = vk::ImageTiling::eOptimal,
                 .usage = vk::ImageUsageFlagBits::eDepthStencilAttachment |
                          vk::ImageUsageFlagBits::eTransferSrc |
                          vk::ImageUsageFlagBits::eTransferDst,
                 .initialLayout = vk::ImageLayout::eUndefined});
            const auto req = D.dev.getImageMemoryRequirements(s.img.img);
            s.img.mem = D.dev.allocateMemory(
                {.allocationSize = req.size,
                 .memoryTypeIndex =
                     FindMemory(req.memoryTypeBits, vk::MemoryPropertyFlagBits::eDeviceLocal)});
            D.dev.bindImageMemory(s.img.img, s.img.mem, 0);
            s.img.view = D.dev.createImageView({.image = s.img.img,
                                                .viewType = vk::ImageViewType::e2D,
                                                .format = dfmt,
                                                .subresourceRange = {s.Aspects(), 0, 1, 0, 1}});
            ds_staging = &fr.NewBuffer(s.ZBytes() + s.SBytes(),
                                       vk::BufferUsageFlagBits::eTransferSrc);
            FillDepthStaging(s, static_cast<u8*>(ds_staging->map));
            dsurf = new_dsurf.get();
            ds_upload = true;
        }

        // DB_DEPTH_CONTROL / DB_STENCIL_CONTROL / DB_STENCILREFMASK(_BF)
        const auto& dc = d.control;
        const bool z_test = has_z && dc.depth_enable && !d.clear_depth;
        const bool z_write = z_test && dc.depth_write_enable && !d.z_read_only;
        const bool s_test = has_s && dc.stencil_enable && !d.clear_stencil;
        const auto& so = d.stencil_ops;
        const auto face = [&](AmdGpu::StencilFunc fail, AmdGpu::StencilFunc zpass,
                              AmdGpu::StencilFunc zfail, AmdGpu::CompareFunc func,
                              const AmdGpu::StencilRefMask& rm) {
            using SF = AmdGpu::StencilFunc;
            // GCN has one test value and one op value; Vulkan one reference.
            const bool op_val = fail == SF::ReplaceOp || zpass == SF::ReplaceOp ||
                                zfail == SF::ReplaceOp;
            return vk::StencilOpState{.failOp = MapStencilOp(fail),
                                      .passOp = MapStencilOp(zpass),
                                      .depthFailOp = MapStencilOp(zfail),
                                      .compareOp = vk::CompareOp(u32(func)),
                                      .compareMask = rm.stencil_mask,
                                      .writeMask = d.stencil_read_only ? 0u
                                                                       : u32(rm.stencil_write_mask),
                                      .reference = op_val ? rm.stencil_op_val
                                                          : rm.stencil_test_val};
        };
        const auto front = face(so.stencil_fail_front, so.stencil_zpass_front,
                                so.stencil_zfail_front, dc.stencil_ref_func, d.front);
        const auto back = dc.backface_enable
                              ? face(so.stencil_fail_back, so.stencil_zpass_back,
                                     so.stencil_zfail_back, dc.stencil_bf_func, d.back)
                              : front;
        ds = vk::PipelineDepthStencilStateCreateInfo{
            .depthTestEnable = z_test,
            .depthWriteEnable = z_write,
            .depthCompareOp = vk::CompareOp(u32(dc.depth_func)),
            .stencilTestEnable = s_test,
            .front = front,
            .back = back};
        const bool s_write = s_test && (front.writeMask || back.writeMask);
        ds_writes = z_write || s_write || (has_z && d.clear_depth) || (has_s && d.clear_stencil);
    }
    const bool ds_has_z = dsurf && dsurf->has_z;
    const bool ds_has_s = dsurf && dsurf->has_s;
    u32 rt_w = 0, rt_h = 0;
    if (!job.targets.empty()) {
        rt_w = job.targets[0].width;
        rt_h = job.targets[0].height;
        if (dsurf) {
            rt_w = std::min(rt_w, dsurf->width);
            rt_h = std::min(rt_h, dsurf->height);
        }
    } else {
        rt_w = dsurf->width;
        rt_h = dsurf->height;
    }

    // ---- pipeline
    const auto module = [&](const TranslatedShader& ts) {
        const auto m = D.dev.createShaderModule(
            {.codeSize = ts.spirv.size() * 4, .pCode = ts.spirv.data()});
        fr.modules.push_back(m);
        return m;
    };
    std::vector<vk::PipelineShaderStageCreateInfo> stages = {
        {.stage = vk::ShaderStageFlagBits::eVertex, .module = module(*vs), .pName = "main"}};
    if (ps) {
        stages.push_back(
            {.stage = vk::ShaderStageFlagBits::eFragment, .module = module(*ps), .pName = "main"});
    }
    // RectList / QuadList have no Vulkan topology: draw them as 3- or
    // 4-point patches through the recompiler's auxiliary TCS (which builds
    // the implied 4th corner and its interpolants) and a passthrough TES.
    pt.Lap(kTargets);
    const bool rect = job.prim_type == GNM_PRIM_RECTLIST;
    const bool quad = job.prim_type == GNM_PRIM_QUADLIST;
    const vk::PipelineTessellationStateCreateInfo tess{.patchControlPoints = rect ? 3u : 4u};
    if (rect || quad) {
        if (!D.tessellation) {
            Fail("RectList/QuadList need tessellation shaders, which this GPU lacks");
        }
        using Shader::Backend::SPIRV::AuxShaderType;
        static const Shader::FragmentRuntimeInfo no_fs{};
        const auto& fs = ps ? ps->runtime.fs_info : no_fs;
        const auto aux = [&](AuxShaderType type) {
            const auto code = Shader::Backend::SPIRV::EmitAuxilaryTessShader(type, fs);
            const auto m =
                D.dev.createShaderModule({.codeSize = code.size() * 4, .pCode = code.data()});
            fr.modules.push_back(m);
            return m;
        };
        stages.insert(stages.begin() + 1,
                      {{.stage = vk::ShaderStageFlagBits::eTessellationControl,
                        .module = aux(rect ? AuxShaderType::RectListTCS
                                           : AuxShaderType::QuadListTCS),
                        .pName = "main"},
                       {.stage = vk::ShaderStageFlagBits::eTessellationEvaluation,
                        .module = aux(AuxShaderType::PassthroughTES),
                        .pName = "main"}});
    }
    const vk::PipelineVertexInputStateCreateInfo vi{
        .vertexBindingDescriptionCount = u32(vbinds.size()),
        .pVertexBindingDescriptions = vbinds.data(),
        .vertexAttributeDescriptionCount = u32(vattrs.size()),
        .pVertexAttributeDescriptions = vattrs.data()};
    const vk::PipelineInputAssemblyStateCreateInfo ia{
        .topology = (rect || quad) ? vk::PrimitiveTopology::ePatchList : MapPrim(job.prim_type)};
    // Depth range: window z = z_ndc * zscale + zoffset. With GL-style clip
    // space the VS remaps z to (z + w) / 2, so the range is zoffset +- zscale.
    const float zlo = job.clip_minus_w_to_w ? job.vp_zoffset - job.vp_zscale : job.vp_zoffset;
    const float zhi = job.vp_zoffset + job.vp_zscale;
    const vk::Viewport vp{.x = job.vp_xoffset - job.vp_xscale,
                          .y = job.vp_yoffset - job.vp_yscale,
                          .width = job.vp_xscale * 2.0f,
                          .height = job.vp_yscale * 2.0f,
                          .minDepth = std::clamp(zlo, 0.0f, 1.0f),
                          .maxDepth = std::clamp(zhi, 0.0f, 1.0f)};
    const vk::Rect2D sc{{0, 0}, {rt_w, rt_h}};
    const vk::PipelineViewportStateCreateInfo vps{
        .viewportCount = 1, .pViewports = &vp, .scissorCount = 1, .pScissors = &sc};
    const vk::PipelineRasterizationStateCreateInfo rs{.polygonMode = vk::PolygonMode::eFill,
                                                      .cullMode = vk::CullModeFlagBits::eNone,
                                                      .frontFace = vk::FrontFace::eClockwise,
                                                      .lineWidth = 1.0f};
    const vk::PipelineMultisampleStateCreateInfo ms{.rasterizationSamples =
                                                        vk::SampleCountFlagBits::e1};
    const vk::PipelineColorBlendStateCreateInfo cb{
        .attachmentCount = num_slots,
        .pAttachments = blends.data(),
        .blendConstants = job.blend_constants};
    const vk::PipelineRenderingCreateInfo rci{
        .colorAttachmentCount = num_slots,
        .pColorAttachmentFormats = formats.data(),
        .depthAttachmentFormat = ds_has_z ? dsurf->fmt : vk::Format::eUndefined,
        .stencilAttachmentFormat = ds_has_s ? dsurf->fmt : vk::Format::eUndefined};
    const auto pres = D.dev.createGraphicsPipeline({}, {.pNext = &rci,
                                                        .stageCount = u32(stages.size()),
                                                        .pStages = stages.data(),
                                                        .pVertexInputState = &vi,
                                                        .pInputAssemblyState = &ia,
                                                        .pTessellationState =
                                                            (rect || quad) ? &tess : nullptr,
                                                        .pViewportState = &vps,
                                                        .pRasterizationState = &rs,
                                                        .pMultisampleState = &ms,
                                                        .pDepthStencilState = &ds,
                                                        .pColorBlendState = &cb,
                                                        .layout = fr.pipe_layout});
    if (pres.result != vk::Result::eSuccess) {
        Fail("pipeline creation failed: " + vk::to_string(pres.result));
    }
    fr.pipeline = pres.value;
    pt.Lap(kPipeline);

    // ---- index buffer
    Buffer* ib = nullptr;
    if (job.index_address) {
        if (job.index_size != 2 && job.index_size != 4) {
            Fail("bad index size");
        }
        const size_t n = size_t(job.vertex_count) * job.index_size;
        ib = &fr.NewBuffer(n, vk::BufferUsageFlagBits::eIndexBuffer);
        std::memcpy(ib->map, reinterpret_cast<const void*>(uintptr_t(job.index_address)), n);
    }

    // ---- record (into the shared per-submit batch command buffer)
    auto c = BeginBatch();
    RecordUploads(c, bd);
    std::vector<vk::RenderingAttachmentInfo> atts(num_slots);
    for (const auto& r : res) {
        const auto& t = *r.t;
        if (r.surf && !r.upload) {
            // resident: already holds the target's contents (previous draw)
            Barrier(c, r.img->img, L::eColorAttachmentOptimal, L::eColorAttachmentOptimal,
                    S2::eColorAttachmentOutput, A2::eColorAttachmentWrite,
                    S2::eColorAttachmentOutput,
                    A2::eColorAttachmentRead | A2::eColorAttachmentWrite);
        } else if (r.surf) {
            Barrier(c, r.img->img, L::eUndefined, L::eTransferDstOptimal, S2::eTopOfPipe, {},
                    S2::eCopy, A2::eTransferWrite);
            c.copyBufferToImage(r.staging->buf, r.img->img, L::eTransferDstOptimal,
                                CopyRegion(t.width, t.height, r.row_texels, false));
            Barrier(c, r.img->img, L::eTransferDstOptimal, L::eColorAttachmentOptimal, S2::eCopy,
                    A2::eTransferWrite, S2::eColorAttachmentOutput,
                    A2::eColorAttachmentRead | A2::eColorAttachmentWrite);
        } else {
            Barrier(c, r.img->img, L::eUndefined, L::eColorAttachmentOptimal, S2::eTopOfPipe, {},
                    S2::eColorAttachmentOutput, A2::eColorAttachmentWrite);
        }
        vk::ClearValue clear{};
        std::memcpy(&clear.color.float32, t.clear.data(), sizeof(float) * 4);
        atts[t.slot] = {.imageView = r.img->view,
                        .imageLayout = L::eColorAttachmentOptimal,
                        .loadOp = (t.load && r.surf) ? vk::AttachmentLoadOp::eLoad
                                                     : vk::AttachmentLoadOp::eClear,
                        .storeOp = vk::AttachmentStoreOp::eStore,
                        .clearValue = clear};
    }
    vk::RenderingAttachmentInfo datt{};
    if (dsurf) {
        const auto asp = dsurf->Aspects();
        if (ds_upload) {
            Barrier(c, dsurf->img.img, L::eUndefined, L::eTransferDstOptimal, S2::eTopOfPipe, {},
                    S2::eCopy, A2::eTransferWrite, asp);
            c.copyBufferToImage(ds_staging->buf, dsurf->img.img, L::eTransferDstOptimal,
                                dsurf->Copies());
            Barrier(c, dsurf->img.img, L::eTransferDstOptimal, L::eDepthStencilAttachmentOptimal,
                    S2::eCopy, A2::eTransferWrite, kDepthStages, kDepthAccess, asp);
        } else {
            Barrier(c, dsurf->img.img, L::eDepthStencilAttachmentOptimal,
                    L::eDepthStencilAttachmentOptimal, kDepthStages,
                    A2::eDepthStencilAttachmentWrite, kDepthStages, kDepthAccess, asp);
        }
        datt = {.imageView = dsurf->img.view,
                .imageLayout = L::eDepthStencilAttachmentOptimal,
                .loadOp = vk::AttachmentLoadOp::eLoad,
                .storeOp = vk::AttachmentStoreOp::eStore};
    }
    c.beginRendering({.renderArea = sc,
                      .layerCount = 1,
                      .colorAttachmentCount = num_slots,
                      .pColorAttachments = atts.data(),
                      .pDepthAttachment = ds_has_z ? &datt : nullptr,
                      .pStencilAttachment = ds_has_s ? &datt : nullptr});
    if (dsurf && ((ds_has_z && job.depth->clear_depth) || (ds_has_s && job.depth->clear_stencil))) {
        // DB_RENDER_CONTROL depth/stencil clear: the draw writes the clear values
        // (DB_DEPTH_CLEAR / DB_STENCIL_CLEAR) instead of its own; drivers issue
        // it as a full-target rectangle, so clear the render area.
        vk::ImageAspectFlags asp{};
        if (ds_has_z && job.depth->clear_depth) {
            asp |= vk::ImageAspectFlagBits::eDepth;
        }
        if (ds_has_s && job.depth->clear_stencil) {
            asp |= vk::ImageAspectFlagBits::eStencil;
        }
        const vk::ClearAttachment ca{
            .aspectMask = asp,
            .clearValue = vk::ClearDepthStencilValue{job.depth->depth_clear,
                                                     job.depth->stencil_clear}};
        const vk::ClearRect cr{.rect = sc, .baseArrayLayer = 0, .layerCount = 1};
        c.clearAttachments(ca, cr);
    }
    c.bindPipeline(vk::PipelineBindPoint::eGraphics, fr.pipeline);
    c.bindDescriptorSets(vk::PipelineBindPoint::eGraphics, fr.pipe_layout, 0, set, {});
    Shader::PushData push{};
    push.xoffset = job.vp_xoffset;
    push.yoffset = job.vp_yoffset;
    push.xscale = job.vp_xscale;
    push.yscale = job.vp_yscale;
    Shader::Backend::Bindings pb{};
    if (ps) {
        ps->info->PushUd(pb, push);
    }
    vs->info->PushUd(pb, push);
    c.pushConstants(fr.pipe_layout, vk::ShaderStageFlagBits::eAllGraphics, 0, sizeof(push),
                    &push);
    const u32 instances = std::max(1u, job.instance_count);
    if (!vbufs.empty()) {
        const std::vector<vk::DeviceSize> offs(vbufs.size(), 0);
        c.bindVertexBuffers(0, vbufs, offs);
    }
    if (ib) {
        c.bindIndexBuffer(ib->buf, 0,
                          job.index_size == 2 ? vk::IndexType::eUint16 : vk::IndexType::eUint32);
        c.drawIndexed(job.vertex_count, instances, 0, s32(first_vertex), first_instance);
    } else {
        c.draw(job.vertex_count, instances, first_vertex, first_instance);
    }
    c.endRendering();
    for (const auto& r : res) {
        if (r.surf) {
            continue; // stays resident; written back by WriteBack()
        }
        Barrier(c, r.img->img, L::eColorAttachmentOptimal, L::eTransferSrcOptimal,
                S2::eColorAttachmentOutput, A2::eColorAttachmentWrite, S2::eCopy,
                A2::eTransferRead);
        c.copyImageToBuffer(r.img->img, L::eTransferSrcOptimal, r.staging->buf,
                            CopyRegion(r.t->width, r.t->height, r.row_texels, false));
    }
    RecordImageWriteBacks(c, bd);
    RecordHostBarrier(c);
    pt.Lap(kRecord);   // c is the shared batch buffer: FlushBatch() ends/submits it

    // Record-time bookkeeping (no GPU dependency): a later draw in this same
    // batch must see this draw's rendered targets as resident right away.
    for (const auto& r : res) {
        if (r.surf) {
            r.surf->dirty = true;
        } else if (r.t->readback) {
            // non-resident target with a read-back: copy once the GPU is done
            g_batch.readbacks.push_back({r.staging, r.t->readback, r.bytes});
        }
    }
    for (auto& s : new_surfaces) {
        g_surfaces.push_back(std::move(s));
    }
    if (dsurf && ds_writes) {
        dsurf->dirty = true;
    }
    if (new_dsurf) {
        g_depth_surfaces.push_back(std::move(new_dsurf));
    }

    // Defer this draw's guest write-backs to the flush and keep its resources
    // alive until then (the recorded commands reference them).
    const bool writes_guest = !bd.buffer_writebacks.empty() || !bd.image_writebacks.empty();
    g_batch.writebacks.push_back(std::move(bd));
    g_batch.frames.push_back(std::move(frp));

    // A draw that writes guest memory through a UAV must have those writes
    // landed before any later draw or packet reads them, so end the batch here.
    if (writes_guest) {
        FlushBatch();
    }
}

void FlushSurfaces(u64 lo, u64 hi) {
    FlushRange(lo, hi);
}

void ReleaseSurfaces() {
    // Finish any draws still batched (also covers a submit whose targets were
    // all non-resident, so the WriteBack loop below would not flush).
    FlushBatch();
    // write everything back first (WriteBack may throw: keep the rest intact)
    for (auto& s : g_surfaces) {
        WriteBack(*s);
    }
    for (auto& s : g_depth_surfaces) {
        WriteBack(*s);
    }
    g_surfaces.clear();
    g_depth_surfaces.clear();
    // Submit boundary: the GPU is idle and every surface is written back, so the
    // whole submit's pooled scratch can now be reused by the next submit.
    PoolResetAll();
}

u32 SurfaceWriteBacks() {
    return g_surface_writebacks;
}

void ExecuteCompute(const ComputeJob& job) {
    // A dispatch may read what earlier draws produced and does its own submit;
    // finish any batched draws first.
    FlushBatch();
    Device& D = Dev();
    if (job.cs.stage != GNM_STAGE_CS) {
        Fail("a compute job needs a CS");
    }
    StageExtras extras{};
    extras.cs_threads = job.threads;
    Shader::Backend::Bindings bnd{};
    const auto cs = Translate(job.cs, D.profile, bnd, &extras);
    FlushForShader(*cs);

    Frame fr{.dev = D.dev};
    Bound bd;
    BindStage(fr, *cs, bd);
    const auto set = MakeSet(fr, bd, vk::ShaderStageFlagBits::eCompute);
    const auto mod =
        D.dev.createShaderModule({.codeSize = cs->spirv.size() * 4, .pCode = cs->spirv.data()});
    fr.modules.push_back(mod);
    const auto pres = D.dev.createComputePipeline(
        {}, {.stage = {.stage = vk::ShaderStageFlagBits::eCompute, .module = mod, .pName = "main"},
             .layout = fr.pipe_layout});
    if (pres.result != vk::Result::eSuccess) {
        Fail("compute pipeline creation failed: " + vk::to_string(pres.result));
    }
    fr.pipeline = pres.value;

    auto c = BeginCmd(fr);
    RecordUploads(c, bd);
    c.bindPipeline(vk::PipelineBindPoint::eCompute, fr.pipeline);
    c.bindDescriptorSets(vk::PipelineBindPoint::eCompute, fr.pipe_layout, 0, set, {});
    Shader::PushData push{};
    Shader::Backend::Bindings pb{};
    cs->info->PushUd(pb, push);
    c.pushConstants(fr.pipe_layout, vk::ShaderStageFlagBits::eCompute, 0, sizeof(push), &push);
    c.dispatch(job.groups[0], job.groups[1], job.groups[2]);
    RecordImageWriteBacks(c, bd);
    RecordHostBarrier(c);
    c.end();
    SubmitAndWait(fr);
    FinishWriteBacks(bd);
}

const Shader::Profile& CurrentProfile() {
    return g_dev ? g_dev->profile : g_default_profile;
}

std::mutex& DeviceMutex() {
    return g_mutex;
}

} // namespace psemu

using namespace psemu;

extern "C" GNM_API int gnm_init(char* err, int errlen) {
    std::lock_guard lk{g_mutex};
    try {
        Dev();
        return 0;
    } catch (const std::exception& e) {
        SetError(err, errlen, e.what());
        return 1;
    }
}

extern "C" GNM_API void gnm_shutdown(void) {
    std::lock_guard lk{g_mutex};
    if (g_dev) {
        g_dev->dev.waitIdle();
        PoolDestroyAll();
        g_dev->dev.destroyCommandPool(g_dev->cmd_pool);
        g_dev->dev.destroy();
        g_dev->instance.destroy();
        g_dev.reset();
    }
}

extern "C" GNM_API int gnm_device_name(char* out, int cap) {
    std::lock_guard lk{g_mutex};
    try {
        SetError(out, cap, Dev().name);
        return 0;
    } catch (const std::exception& e) {
        SetError(out, cap, e.what());
        return 1;
    }
}

extern "C" GNM_API int gnm_profile(char* out, int outlen, int reset) {
    std::string s = fmt::format("draws={} flushes={}", psemu::g_prof_draws, psemu::g_flush_count);
    for (int i = 0; i < psemu::kNumPhases; ++i) {
        s += fmt::format(" {}={:.0f}ms", psemu::kPhaseNames[i], psemu::g_prof_ms[i]);
    }
    if (out && outlen > 0) {
        std::snprintf(out, size_t(outlen), "%s", s.c_str());
    }
    if (reset) {
        std::fill(std::begin(psemu::g_prof_ms), std::end(psemu::g_prof_ms), 0.0);
        psemu::g_prof_draws = 0;
        psemu::g_flush_count = 0;
    }
    return 0;
}

extern "C" GNM_API int gnm_draw(const GnmDrawDesc* draw, uint8_t* rgba_out, char* err,
                                int errlen) {
    std::lock_guard lk{g_mutex};
    SehGuard seh;
    try {
        GraphicsJob job;
        job.vs = draw->vs;
        job.ps = draw->ps;
        job.prim_type = draw->prim_type;
        job.vertex_count = draw->vertex_count;
        job.instance_count = std::max(1u, draw->instance_count);
        job.vp_xscale = draw->vp_xscale;
        job.vp_xoffset = draw->vp_xoffset;
        job.vp_yscale = draw->vp_yscale;
        job.vp_yoffset = draw->vp_yoffset;
        ColorTarget t{};
        t.slot = 0;
        t.width = draw->width;
        t.height = draw->height;
        t.pitch = draw->width;
        std::memcpy(t.clear.data(), draw->clear_color, sizeof(float) * 4);
        t.readback = rgba_out;
        job.targets.push_back(t);
        ExecuteGraphics(job);
        FlushBatch();     // standalone draw: no ReleaseSurfaces to flush/read back
        PoolResetAll();   // ...nor to reclaim the pool
        return 0;
    } catch (const std::exception& e) {
        SetError(err, errlen, e.what());
        return 1;
    } catch (...) {
        SetError(err, errlen, "unknown failure");
        return 1;
    }
}
