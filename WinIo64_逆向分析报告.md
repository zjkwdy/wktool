# WinIo64.sys 逆向分析报告

## 1. 基本信息

| 项目 | 内容 |
|------|------|
| 文件名 | WinIo64.sys |
| 架构 | x64 (64位) |
| 基址 | `0x140000000` |
| 镜像大小 | `0x7000` (28 KB) |
| MD5 | `66ab7f46db42bf52db06840ec3b4deb3` |
| 总函数数 | 13 |
| PDB | `D:\Users\heavenluo\Documents\Visual Studio 2017\Projects\WinIo\x64\Release\WinIo64.pdb` |
| 编译环境 | Visual Studio 2017 |
| 依赖模块 | `ntoskrnl.exe`, `HAL.dll` |

---

## 2. 设备名称与符号链接

| 类型 | 名称 |
|------|------|
| **设备名** | `\Device\WinIo` |
| **符号链接** | `\DosDevices\WinIo` |

- 设备创建于 `WinIoDriverEntry` (`0x140001000`)，调用 `IoCreateDevice` 创建，设备类型 `0x8010`
- 符号链接通过 `IoCreateSymbolicLink` 创建
- 卸载时通过 `WinIoDriverUnload` (`0x1400014d4`) 删除符号链接和设备

---

## 3. 主要函数

| 函数 | 地址 | 说明 |
|------|------|------|
| `DriverEntry` | `0x140005000` | 入口点，调用 `WinIoDriverEntry` |
| `WinIoDriverEntry` | `0x140001000` | 创建设备、符号链接，注册分发函数与卸载例程 |
| `WinIoDispatch` | `0x1400012f8` | IOCTL 主分发函数（IRP_MJ_CREATE/CLOSE/DEVICE_CONTROL） |
| `WinIoMapPhysicalMemory` | `0x1400010c0` | 映射物理内存到用户空间 |
| `WinIoUnmapPhysicalMemory` | `0x1400012ac` | 解除物理内存映射 |
| `WinIoDriverUnload` | `0x1400014d4` | 驱动卸载：删除符号链接和设备对象 |

### 分发函数注册

在 `WinIoDriverEntry` 中注册了以下 IRP 回调：
- `MajorFunction[0]` (IRP_MJ_CREATE) → `WinIoDispatch`
- `MajorFunction[2]` (IRP_MJ_CLOSE) → `WinIoDispatch`
- `MajorFunction[14]` (IRP_MJ_DEVICE_CONTROL) → `WinIoDispatch`
- `DriverUnload` → `WinIoDriverUnload`

所有 IOCTL 使用 **METHOD_BUFFERED** 方式（共用系统缓冲区作为输入输出缓冲）。

---

## 4. IOCTL 完整分析

所有 IOCTL 定义：
```
#define WINIO_DEVICE_TYPE  0x8010
#define WINIO_CTL_CODE(Function) CTL_CODE(WINIO_DEVICE_TYPE, Function, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

---

### 4.1 IOCTL 0x80102040 — 映射物理内存

| 字段 | 值 |
|------|-----|
| CTL_CODE | `CTL_CODE(0x8010, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)` |
| IOCTL | `0x80102040` |
| 输入缓冲区 | 16 字节 |
| 输出缓冲区 | 16 字节（回显输入） |
| 底层函数 | `WinIoMapPhysicalMemory` |

**输入结构 (WINIO_MAP_PHYSMEM_INPUT)：**
```c
typedef struct {
    ULONG_PTR        Size;              // +0x00 (8 bytes): 要映射的字节数
    PHYSICAL_ADDRESS PhysicalAddress;   // +0x08 (8 bytes): 源物理总线地址
} WINIO_MAP_PHYSMEM_INPUT;
```

**输出结构：**
```c
typedef struct {
    ULONG_PTR        Size;              // +0x00: 回显输入的 Size
    PHYSICAL_ADDRESS PhysicalAddress;   // +0x08: 回显输入的 PhysicalAddress
} WINIO_MAP_PHYSMEM_OUTPUT;
```
> 注意：输出缓冲区回显输入内容，映射的虚拟地址通过内部机制使用，未返回给用户。

**内部流程：**
1. 通过 `RtlInitUnicodeString` 初始化 `\Device\PhysicalMemory` 名称
2. `ZwOpenSection` 打开物理内存 Section（权限 `0xF001F`）
3. `ObReferenceObjectByHandle` 获取对象引用
4. `HalTranslateBusAddress` 将总线地址转换为系统物理地址（Isa 总线，一次转换起始地址，一次转换结束地址）
5. `ZwMapViewOfSection` 映射物理内存视图到当前进程（`(HANDLE)-1`）
   - 首次尝试 `PAGE_READWRITE` (`0x204`)，若失败（`STATUS_CONFLICTING_ADDRESSES`）则重试 `PAGE_WRITECOPY` (`0x4`)
6. 返回映射的虚拟地址通过 `a3` 指针参数传出（但 IOCTL 输出未包含此值）

---

### 4.2 IOCTL 0x80102044 — 解除物理内存映射

| 字段 | 值 |
|------|-----|
| CTL_CODE | `CTL_CODE(0x8010, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)` |
| IOCTL | `0x80102044` |
| 输入缓冲区 | 40 字节 |
| 输出缓冲区 | 无 |
| 底层函数 | `WinIoUnmapPhysicalMemory` |

**输入结构 (WINIO_UNMAP_PHYSMEM_INPUT)：**
```c
typedef struct {
    ULONG_PTR unused1;          // +0x00 (8 bytes): 忽略（覆盖栈上 Src[0]）
    ULONG_PTR unused2;          // +0x08 (8 bytes): 忽略（覆盖栈上 Src[1]）
    HANDLE    SectionHandle;    // +0x10 (8 bytes): 映射时获得的 Section 句柄
    PVOID     MappedAddress;    // +0x18 (8 bytes): 映射时获得的虚拟地址
    PVOID     ObjectPointer;    // +0x20 (8 bytes): 映射时获得的对象指针
} WINIO_UNMAP_PHYSMEM_INPUT;
```

> **实现细节：** 驱动将输入缓冲区通过 `memmove` 拷贝到栈上 `Src` 数组起始地址，该数组大小为 16 字节。输入数据超过 16 字节时会越界覆盖栈上后续的 `Handle`、`v18`、`v19` 局部变量，从而传递解映射所需的三个参数。这是一种利用栈溢出的 hack 式参数传递。

**内部流程：**
1. `ZwUnmapViewOfSection` 解除虚拟地址映射
2. `ObfDereferenceObject` 释放对象引用
3. `ZwClose` 关闭 Section 句柄

---

### 4.3 IOCTL 0x80102050 — 端口输入 (IN 指令)

| 字段 | 值 |
|------|-----|
| CTL_CODE | `CTL_CODE(0x8010, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)` |
| IOCTL | `0x80102050` |
| 输入缓冲区 | 7 字节 |
| 输出缓冲区 | 4 字节（读取的值） |

**输入结构 (WINIO_PORT_INPUT)：**
```c
typedef struct {
    WORD  PortAddress;   // +0x00 (2 bytes): I/O 端口地址
    DWORD Reserved;      // +0x02 (4 bytes): 未使用（对于 IN 操作）
    BYTE  SizeFlag;      // +0x06 (1 byte):  数据大小标志
} WINIO_PORT_INPUT;
```

**SizeFlag 取值：**
| 值 | 指令 | 读取字节数 |
|----|------|-----------|
| 1 | `IN AL, DX` | 1 字节 (BYTE) |
| 2 | `IN AX, DX` | 2 字节 (WORD) |
| 4 | `IN EAX, DX` | 4 字节 (DWORD) |

**输出结构 (WINIO_PORT_OUTPUT)：**
```c
typedef struct {
    DWORD Data;   // +0x00 (4 bytes): 从 I/O 端口读取的值
} WINIO_PORT_OUTPUT;
```

**内部流程：**
1. 拷贝输入到栈上结构
2. 根据 `SizeFlag` 执行对应的 `__inbyte` / `__inword` / `__indword` 指令
3. 结果写入输出缓冲区前 4 字节，`IoStatus.Information = 4`

---

### 4.4 IOCTL 0x80102054 — 端口输出 (OUT 指令)

| 字段 | 值 |
|------|-----|
| CTL_CODE | `CTL_CODE(0x8010, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)` |
| IOCTL | `0x80102054` |
| 输入缓冲区 | 7 字节 |
| 输出缓冲区 | 无 |

**输入结构 (WINIO_PORT_OUTPUT)：**
```c
typedef struct {
    WORD  PortAddress;   // +0x00 (2 bytes): I/O 端口地址
    DWORD Data;          // +0x02 (4 bytes): 要写入端口的数据
    BYTE  SizeFlag;      // +0x06 (1 byte):  数据大小标志
} WINIO_PORT_OUTPUT;
```

**SizeFlag 取值：**
| 值 | 指令 | 写入字节数 |
|----|------|-----------|
| 1 | `OUT DX, AL` | 1 字节 (BYTE) |
| 2 | `OUT DX, AX` | 2 字节 (WORD) |
| 4 | `OUT DX, EAX` | 4 字节 (DWORD) |

**内部流程：**
1. 拷贝输入到栈上结构
2. 根据 `SizeFlag` 执行对应的 `__outbyte` / `__outword` / `__outdword` 指令
3. 无输出数据，`IoStatus.Information = 0`

---

## 5. IOCTL 对照速查表

| IOCTL | 功能 | 输入大小 | 输出大小 | SizeFlag |
|-------|------|----------|----------|----------|
| `0x80102040` | 映射物理内存 | 16 字节 | 16 字节 | - |
| `0x80102044` | 解除映射 | 40 字节 | 无 | - |
| `0x80102050` | 端口读 (IN) | 7 字节 | 4 字节 | 1/2/4 |
| `0x80102054` | 端口写 (OUT) | 7 字节 | 无 | 1/2/4 |

---

## 6. 依赖的 API 列表

| API | 所属模块 | 用途 |
|-----|---------|------|
| `IoCreateDevice` | ntoskrnl | 创建设备对象 |
| `IoCreateSymbolicLink` | ntoskrnl | 创建符号链接 |
| `IoDeleteDevice` | ntoskrnl | 删除设备对象 |
| `IoDeleteSymbolicLink` | ntoskrnl | 删除符号链接 |
| `IofCompleteRequest` | ntoskrnl | 完成 IRP 请求 |
| `RtlInitUnicodeString` | ntoskrnl | 初始化 UNICODE_STRING |
| `ZwOpenSection` | ntoskrnl | 打开物理内存 Section |
| `ZwMapViewOfSection` | ntoskrnl | 映射 Section 视图 |
| `ZwUnmapViewOfSection` | ntoskrnl | 解除 Section 视图映射 |
| `ZwClose` | ntoskrnl | 关闭句柄 |
| `ObReferenceObjectByHandle` | ntoskrnl | 通过句柄获取对象引用 |
| `ObfDereferenceObject` | ntoskrnl | 释放对象引用 |
| `HalTranslateBusAddress` | HAL | 转换总线地址到系统物理地址 |

---

## 7. 安全注意事项

1. **IOCTL 0x80102040** 使用 `\Device\PhysicalMemory` 的 `ZwOpenSection` 配合 `ZwMapViewOfSection` 将物理内存映射到用户态进程，可以获得任意物理内存的访问权限，存在严重安全隐患。
2. **IOCTL 0x80102044** 利用栈溢出传递解映射参数（输入 40 字节覆盖栈上 16 字节数组之后的局部变量），设计极其脆弱且不安全。
3. **IOCTL 0x80102050 / 0x80102054** 允许用户态直接执行 `IN`/`OUT` 指令访问任意 I/O 端口，可被用于硬件操作或提权攻击。
4. 仅有 `FILE_ANY_ACCESS` 权限控制，没有额外的访问检查。
