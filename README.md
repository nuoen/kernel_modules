# kernel_modules

这是一个 Android 内核模块实验仓库，主要用于验证和练习以下方向：

- 内核模块开发
- 内核符号解析
- `/proc` 导出
- `kprobe` / `kretprobe`
- ftrace hook
- syscall table hook

这个仓库更偏研究和调试用途，不是生产环境可直接使用的稳定模块集合。

## 项目结构

- `hello/`
  最小内核模块示例，用于验证模块编译、加载和卸载流程。
- `cpuinfo/`
  通过 `kprobe` 获取 `kallsyms_lookup_name`，再继续解析 CPU 相关符号。
- `cdevcpuinfo/`
  通过字符设备导出 CPU 信息的实验模块。
- `proccpuinfo/`
  通过 `/proc` 导出 CPU 信息的实验模块。
- `sysmodule/`
  解析内核内部符号并修改相关内核状态的小型实验模块。
- `hookmodule/`
  仓库里风险最高的模块，混合使用 `kprobe`、`kretprobe`、ftrace 和 syscall table patch。

## 内核源码获取

内核源码拉取可参考：

- [Pixel GKI kernel branches](https://source.android.com/docs/setup/build/building-pixel-kernels#pixel-gki-kernel-branches)
- [android-gs-akita-6.1-android16 manifest](https://android.googlesource.com/kernel/manifest/+/refs/heads/android-gs-akita-6.1-android16)

拉取命令如下：

```bash
repo init -u https://android.googlesource.com/kernel/manifest \
  -b android-gs-akita-6.1-android16-beta
repo sync
```

## 编译

当前仓库是在 Android GKI 工程下使用 Bazel + Kleaf 编译，主流程以 Bazel 为准。

每个模块目录都包含自己的 `BUILD.bazel`，例如：

- [hello/BUILD.bazel](/Users/nuoen/Documents/AndroidSecurity/tools/kernel_modules/hello/BUILD.bazel)
- [hookmodule/BUILD.bazel](/Users/nuoen/Documents/AndroidSecurity/tools/kernel_modules/hookmodule/BUILD.bazel)

### Bazel 编译命令

如果要编译一个可加载模块，例如 `hello`，可以使用：

```sh
tools/bazel run \
  --config=akita \
  --config=use_source_tree_aosp \
  --config=no_download_gki_fips140 \
  //modules/hello:hello_dist
```

如果要编译 `hookmodule`，可以使用：

```sh
tools/bazel run \
  --config=akita \
  --config=use_source_tree_aosp \
  --config=no_download_gki_fips140 \
  //modules/hookmodule:hookmodule_dist \
  --gki_build_config_fragment=//private/devices/google/akita:akita_gki.fragment \
  --defconfig_fragment=//private/devices/google/akita:akita_gki.fragment \
  --sandbox_debug
```

### `BUILD.bazel` 组织方式

`hello` 模块的 `BUILD.bazel` 是一个标准的 Kleaf 组织方式，核心包括：

1. `filegroup`
   收集 `.c`、`.h` 和 `Kbuild` 源文件。
2. `kernel_module`
   定义模块本体和产物 `.ko`。
3. `copy_to_dist_dir`
   把产物复制到 dist 输出目录。
4. `kernel_modules_install`
   把模块纳入内核模块安装流程。

示例代码如下：

```python
load("@//build/kernel/kleaf:kernel.bzl", "kernel_module", "kernel_modules_install")
load("//build/bazel_common_rules/dist:dist.bzl", "copy_to_dist_dir")

package(
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "lkm_sources",
    srcs = glob(
        [
            "**/*.c",
            "**/*.h",
            "Kbuild",
        ],
        exclude = [
            "BUILD.bazel*",
            "**/*.bzl",
            ".gid/**",
        ],
    ),
)

kernel_module(
    name = "hello",
    srcs = [":lkm_sources"],
    outs = ["hello.ko"],
    kernel_build = "//private/devices/google/akita:kernel",
)

copy_to_dist_dir(
    name = "hello_dist",
    data = [":hello"],
    dist_dir = "out/hello",
    flat = True,
    log = "info",
)

kernel_modules_install(
    name = "hello_install",
    kernel_build = "//private/devices/google/akita:kernel",
    kernel_modules = [
        ":hello",
    ],
)
```

## 加载与卸载

模块编译完成后，可以手动加载：

```sh
insmod hookmodule.ko
rmmod hookmodule
```

查看日志建议使用：

```sh
dmesg | tail -n 100
```

## 说明

这个仓库更适合作为实验环境和问题复现环境，而不是稳定的生产模块集合。不同设备、不同内核版本、不同厂商补丁树上的行为差异会很大，使用时要以目标内核源码和实际调用链为准。
