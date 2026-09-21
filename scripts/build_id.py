Import("env")
import subprocess


def git(*args):
    try:
        return subprocess.check_output(["git"] + list(args), text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


sha = git("rev-parse", "--short=8", "HEAD") or "nogit"
epoch = git("log", "-1", "--format=%ct") or "0"
env.Append(CPPDEFINES=[("AH_GIT_SHA", env.StringifyMacro(sha)), ("AH_BUILD_EPOCH", epoch + "UL")])
env["ENV"]["SOURCE_DATE_EPOCH"] = epoch
print("[build_id] AH_GIT_SHA=%s AH_BUILD_EPOCH=%s SOURCE_DATE_EPOCH=%s" % (sha, epoch, epoch))
