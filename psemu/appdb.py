"""Provisioning of the shell's application database (/priv/mms/app.db), the way the system's
DB-preparation / app-install services populate it on a console.

The schema is the one the shell's own engine defines (strings in eboot.bin):

* tbl_version(category, status): the engine reads it by category into a version struct and
  rejects the DB unless it matches the engine's expected versions (appver 68, locale 1, region 0,
  appinfokeyver 5, appinfover 1, appbrowsever 23).
* tbl_appinfo(titleId, key, val), tbl_cmdfunc: per-title attribute rows / command queue.
* per-user tables, name suffix = the user id as %010d: tbl_appbrowse_<uid> (one row per title the
  user's home screen can show), tbl_addon_<uid> (entitlements), tbl_info_<uid> (key/value).

Titles come from the firmware: every app directory with a sce_sys/param.sfo (system applications
such as the browser, library, media player). Nothing here is game data; it is the catalogue the
system software itself would register for its built-in applications.
"""
import glob
import os
import sqlite3
import tempfile

from .sfo import read_sfo

# category -> value: the versions DbAccessor::Init expects (read at runtime from the engine)
VERSIONS = (("appver", 68), ("locale", 1), ("region", 0), ("appinfokeyver", 5),
            ("appinfover", 1), ("appbrowsever", 23))

DDL_BASE = (
    "CREATE TABLE IF NOT EXISTS tbl_version(category TEXT NOT NULL,status INT,PRIMARY KEY(category));"
    "CREATE TABLE IF NOT EXISTS tbl_appinfo(titleId TEXT NOT NULL,key INT NOT NULL,val,PRIMARY KEY(titleId, key));"
    "CREATE TABLE IF NOT EXISTS tbl_cmdfunc (idx INT NOT NULL,cmdMsg BLOB NOT NULL,titleIdList BLOB,PRIMARY KEY(idx));"
)

# the three per-user table bodies, verbatim from the engine
DDL_APPBROWSE = (
    "(titleId TEXT NOT NULL,contentId TEXT,titleName TEXT COLLATE NOCASE,metaDataPath TEXT,"
    "lastAccessTime DATETIME,contentStatus INT,onDisc INT,parentalLevel INT,visible INT,"
    "sortPriority INT,pathInfo INT,lastAccessIndex INT,dispLocation INT,canRemove INT,category TEXT,"
    "contentType INT,pathInfo2 INT,presentBoxStatus INT,entitlement INT,thumbnailUrl TEXT,"
    "lastUpdateTime TEXT,playableDate DATETIME,contentSize INT,installDate DATETIME,platform INT,"
    "uiCategory TEXT,skuId TEXT,disableLiveDetail INT,linkType INT,linkUri TEXT,"
    "serviceIdAddCont1 TEXT,serviceIdAddCont2 TEXT,serviceIdAddCont3 TEXT,serviceIdAddCont4 TEXT,"
    "serviceIdAddCont5 TEXT,serviceIdAddCont6 TEXT,serviceIdAddCont7 TEXT,folderType INT,"
    "folderInfo TEXT,parentFolderId TEXT,positionInFolder INT,activeDate DATETIME,"
    "entitlementTitleName TEXT COLLATE NOCASE,hddLocation INT,externalHddAppStatus INT,"
    "entitlementIdKamaji TEXT,mTime DATETIME,PRIMARY KEY(titleId));"
)
DDL_ADDON = "(entitlementId TEXT NOT NULL,titleId TEXT,subType TEXT,activeDate DATETIME,PRIMARY KEY(entitlementId));"
DDL_INFO = "(key TEXT NOT NULL,value TEXT,PRIMARY KEY(key));"

# firmware directories (relative to the firmware root) that hold application directories
APP_DIRS = ("system_ex/app", "system/vsh/app", "system/sys")


def discover_titles(fw_root):
    """[(title_id, app_dir_relative_to_fw_root, sfo_dict)] for every firmware app with a param.sfo."""
    out = []
    for rel in APP_DIRS:
        for sfo_path in sorted(glob.glob(os.path.join(fw_root, rel, "*", "sce_sys", "param.sfo"))):
            app_dir = os.path.dirname(os.path.dirname(sfo_path))
            try:
                sfo = read_sfo(sfo_path)
            except Exception:
                continue
            tid = sfo.get("TITLE_ID") or os.path.basename(app_dir)
            out.append((tid, os.path.relpath(app_dir, fw_root).replace("\\", "/"), sfo))
    return out


def _num(v):
    """param.sfo values arrive as int or numeric str; 0xFFFFFFFF is a valid 'set' marker."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def disp_location(sfo):
    """The browse table's dispLocation bitmask. param.sfo carries DISP_LOCATION_1 / _2 (the app's
    position in the two display areas; non-zero = shown there, 0xFFFFFFFF = shown, no fixed slot);
    the shell's list queries test bit 0 / bit 1 of dispLocation (`(dispLocation & 1) <> 0` for the
    home content area, `& 2` for the second list), so bit n-1 is set when DISP_LOCATION_n is set.
    An app with neither key is not listed in either area."""
    return (1 if _num(sfo.get("DISP_LOCATION_1")) else 0) | (2 if _num(sfo.get("DISP_LOCATION_2")) else 0)


def _browse_row(tid, rel_dir, sfo, order):
    """One tbl_appbrowse_<uid> row. Values chosen to describe an installed, visible application."""
    return {
        "titleId": tid,
        "contentId": sfo.get("CONTENT_ID", ""),
        "titleName": sfo.get("TITLE", ""),
        # the engine appends the asset file name (icon0.png ...): point at the app's sce_sys dir
        "metaDataPath": "/" + rel_dir + "/sce_sys",
        "parentalLevel": int(sfo.get("PARENTAL_LEVEL", 1)),
        "visible": 1,
        "sortPriority": order,
        "category": sfo.get("CATEGORY", ""),
        "uiCategory": sfo.get("CATEGORY", ""),
        "entitlement": 0,
        # the shell's list queries compare these with =, <> and &: a NULL never matches, so a real
        # row has them set (folderType 0 = not a folder; presentBoxStatus 0 = no present-box state)
        "dispLocation": disp_location(sfo),
        "folderType": 0,
        "presentBoxStatus": 0,
    }


def _appinfo_rows(tid, rel_dir, sfo, order):
    """tbl_appinfo rows (key NAME -> value) for one title. The shell stores the key *names* from
    the engine's key pool in the `key` column (SQLite's dynamic typing allows text in the INT
    column); a '#' prefix marks an integer-valued key. Values come from param.sfo, the rest are
    the state of an installed, never-launched system application."""
    meta = "/" + rel_dir + "/sce_sys"
    return {
        "_title_id": tid,
        "TITLE": sfo.get("TITLE", ""),
        "CONTENT_ID": sfo.get("CONTENT_ID", ""),
        "_metadata_path": meta,
        "PARENTAL_LEVEL": int(sfo.get("PARENTAL_LEVEL", 1)),
        "CATEGORY": sfo.get("CATEGORY", ""),
        "ATTRIBUTE_INTERNAL": int(sfo.get("ATTRIBUTE", 0)),
        "_sort_priority": order,
        "#_contents_status": 0,
        "#_promote_time": 0,
        "#_access_index": 0,
        "#_size": 0,
        "#_mtime": 0,
        "DISP_LOCATION_1": _num(sfo.get("DISP_LOCATION_1")),
        "DISP_LOCATION_2": _num(sfo.get("DISP_LOCATION_2")),
        "_contents_location": 0,
        "_path_info": 0,
        "_path_info_2": 0,
        "_with_ps3_disc": 0,
        "_present_box_status": 0,
        "_contents_ext_type": 0,
        "_uninstallable": 0,
        "_view_category": 0,
        "_disable_live_detail": 0,
        "_hdd_location": 0,
        "_external_hdd_app_status": 0,
    }


def build_app_db(fw_root, user_id=0x10000001, extra_sql=None):
    """Return the bytes of a freshly provisioned app.db."""
    fd, path = tempfile.mkstemp(suffix=".appdb")
    os.close(fd)
    try:
        con = sqlite3.connect(path)
        con.executescript(DDL_BASE)
        con.executemany("REPLACE INTO tbl_version VALUES(?, ?)", VERSIONS)
        uid = "%010d" % user_id
        con.execute(f"CREATE TABLE IF NOT EXISTS tbl_appbrowse_{uid} " + DDL_APPBROWSE)
        con.execute(f"CREATE TABLE IF NOT EXISTS tbl_addon_{uid} " + DDL_ADDON)
        con.execute(f"CREATE TABLE IF NOT EXISTS tbl_info_{uid} " + DDL_INFO)
        for order, (tid, rel, sfo) in enumerate(discover_titles(fw_root)):
            con.executemany("REPLACE INTO tbl_appinfo(titleId, key, val) VALUES(?,?,?)",
                            [(tid, k, v) for k, v in _appinfo_rows(tid, rel, sfo, order).items()])
            if os.environ.get("PSEMU_APPDB_NOBROWSE"):     # dev: let the engine build the browse rows
                continue
            row = _browse_row(tid, rel, sfo, order)
            cols = ",".join(row)
            con.execute(f"REPLACE INTO tbl_appbrowse_{uid}({cols}) VALUES({','.join('?' * len(row))})",
                        list(row.values()))
        if extra_sql and os.path.isfile(extra_sql):           # dev aid: schema/value discovery
            with open(extra_sql, encoding="utf-8") as fh:
                con.executescript(fh.read())
        con.commit()
        con.close()
        with open(path, "rb") as fh:
            return bytearray(fh.read())
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
