SECTIONS {
    .blob 0x0 : {
        *(.text$sc_entry)
        *(.text*)
    }
    /DISCARD/ : { *(.rdata*) *(.data*) *(.bss*) *(.xdata*) *(.pdata*) }
}
