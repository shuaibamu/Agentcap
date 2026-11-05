ENTRY(bench)
MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1M  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 256K }
SECTIONS {
 .text : { KEEP(*(.text.bench)) KEEP(*(.text.bench_boot)) *(.text*) } > FLASH
 .rodata : { *(.rodata*) } > FLASH
 .data : { *(.data*) } > RAM
 .bss : { *(.bss*) *(COMMON) } > RAM
}
