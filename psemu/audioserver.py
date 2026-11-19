"""The audio server's pacing: what libSceAudioOut waits for.

On a console SceAudioSystem (a separate process) mixes the ports' buffers and, each time it has
consumed one period of a port, sets that port's bit in the event flag `sceAudioOutMix<pid>` (bit =
1 << port index; seen: port 7 waits for 0x80, AND mode). sceAudioOutOutput blocks on it, which is
what keeps a game's audio thread running at the output rate.

psemu has no audio mixer (nothing is played), but an event flag whose owner never signals made every
waiter either spin (the old stand-in granted the bits at once: ~750 000 evf_wait calls in 50 s, the
guest starved of CPU) or hang. Waits on it now end at the next period boundary of VIRTUAL time, with
the requested bits set, so an audio thread runs at the real rate and costs almost nothing.
"""

SAMPLE_RATE = 48000
PERIOD_FRAMES = 256                       # the grain libScePsm / most titles open ports with
PERIOD_NS = PERIOD_FRAMES * 1_000_000_000 // SAMPLE_RATE      # 5.333 ms

MIX_EVF_PREFIX = "sceAudioOutMix"


def is_mix_evf(name):
    return name.startswith(MIX_EVF_PREFIX)


def next_period(now_ns):
    """Virtual time of the next period boundary strictly after `now_ns`."""
    return (now_ns // PERIOD_NS + 1) * PERIOD_NS
