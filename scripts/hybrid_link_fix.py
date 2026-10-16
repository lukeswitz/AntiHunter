Import("env")

if env.GetProjectConfig().has_option("env:" + env["PIOENV"], "custom_sdkconfig"):
    env.Replace(LINKFLAGS=[f for f in env["LINKFLAGS"] if f != "-Wl,--wrap=log_printf"])
    print("[hybrid_link_fix] dropped -Wl,--wrap=log_printf (hybrid libs built without CONFIG_LIB_BUILDER_COMPILE)")
