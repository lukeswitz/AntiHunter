import os
Import("env")

# pioarduino links toolchain-riscv32-esp into packages/ as a .pio-link whose bin/ is
# not placed on the build PATH; the real toolchain lives under the core dir's tools/.
# Prepend the real bin so riscv32-esp-elf-g++ resolves. Project-local; touches nothing else.
core = env.subst("$PROJECT_CORE_DIR")
candidates = [
    os.path.join(core, "tools", "toolchain-riscv32-esp", "bin"),
    os.path.join(env.subst("$PROJECT_PACKAGES_DIR"), "toolchain-riscv32-esp", "bin"),
    os.path.join(core, "packages", "toolchain-riscv32-esp", "bin"),
    os.path.expanduser("~/.platformio/tools/toolchain-riscv32-esp/bin"),
]
for path in candidates:
    if os.path.isfile(os.path.join(path, "riscv32-esp-elf-g++")):
        env.PrependENVPath("PATH", path)
        print("[c5] toolchain PATH += %s" % path)
        break
