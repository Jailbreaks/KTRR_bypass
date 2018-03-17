for (int i = 0; i < gadget_size/4; i++) {
        if (!foundx0 && gadget_dump[i] == 0xaa0303e0  && gadget_dump[i+1] == 0xd61f0080) {
            printf("SETX0 %llx\n", gadget_base+i*4);
            foundx0=1;
        }
        
        if (!foundblx0 && gadget_dump[i] == 0x8b160000  && gadget_dump[i+1] == 0xcb170000 && gadget_dump[i+2] == 0xd61f0000) {
            printf("BLX0 %llx\n", gadget_base+i*4 + 12);
            
            uint64_t ttbr0 = find_register_value((uint32_t*)get_data_for_mode(0, SearchTextExec), i*4+12 + 24, text_exec_base, 0);
            uint64_t ttbr1 = find_register_value((uint32_t*)get_data_for_mode(0, SearchTextExec), i*4+12 + 24, text_exec_base, 1);

            uint64_t vpt = (i*4) & ~(0xFFF);
            
            vpt += 8;
            
            
            uint64_t retv1 = find_register_value((uint32_t*)get_data_for_mode(0, SearchTextExec), vpt, text_exec_base, 30);
            vpt += 12;
            uint64_t retv2 = find_register_value((uint32_t*)get_data_for_mode(0, SearchTextExec), vpt, text_exec_base, 30);

            
            uint64_t lol = find_reference((uint32_t*)get_data_for_mode(0, SearchTextExec), gadget_size, text_exec_base, text_exec_base+ vpt - (8+12));
            uint64_t regv = find_register_value((uint32_t*)get_data_for_mode(0, SearchTextExec), lol, text_exec_base, 20);

            uint64_t ladrp = find_prev_instruction_matching((uint32_t*)get_data_for_mode(0, SearchTextExec), i*4-12, 64, insn_is_adrp_64);
            uint64_t regvz = find_register_value((uint32_t*)get_data_for_mode(0, SearchTextExec), ladrp+4, text_exec_base, 0);

            assert(retv1);
            assert(retv2);
            printf("VBAR %llx\n", regvz);
            printf("ENTRYF %llx\n", regv);
            printf("ENTRY1 %llx\n", retv1);
            printf("ENTRY2 %llx\n", retv2);
            printf("TTBR_1R %llx\n", ttbr1);
            printf("TTBR_0R %llx\n", ttbr0);

            foundblx0=1;
        }
        if (gadget_dump[i] == 0xf9401900) {
            if (gadget_dump[i+1] == 0xf9400008) {
                if (gadget_dump[i+2] == 0xf9406501) {
                    if (gadget_dump[i+3] == 0xd61f0020) {
                        printf("DISPATCH %llx\n", gadget_base+i*4);
                        founddispatch++;
                    }
                }
            }
        }
        if (!gdgt0&&gadget_dump[i] == 0xaa1303e0) {
            if (gadget_dump[i+1] == 0xa9417bfd) {
                if (gadget_dump[i+2] == 0xa8c24ff4) {
                    if (gadget_dump[i+3] == 0xd65f03c0) {
                        printf("POP_X20_19_29_30 %llx\n", gadget_base+i*4);
                        gdgt0=1;
                    }
                }
            }
        }
        if (!gdgt1&&gadget_dump[i] == 0xa8c17bfd) {
            if (gadget_dump[i+1] == 0xd65f03c0) {
                printf("POP_X29_30 %llx\n", gadget_base+i*4);
                gdgt1=1;
            }
        }
        if (!gdgt3&&gadget_dump[i] == 0xa8c17bfd) {
            if (gadget_dump[i+1] == 0xd61f0040) {
                printf("POPBR_X2_X29_30 %llx\n", gadget_base+i*4);
                gdgt3=1;
            }
        }
        if (!gdgt4&&gadget_dump[i] == 0xd101c3a0) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("SUBX0 %llx\n", gadget_base+i*4);
                gdgt4=1;
            }
        }
        if (!gdgt5&&gadget_dump[i] == 0xaa0003f6) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("SETX22 %llx\n", gadget_base+i*4);
                gdgt5=1;
            }
        }
        if (!gdgt7&&gadget_dump[i] == 0xaa1503e0) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("MOVX0X21 %llx\n", gadget_base+i*4);
                gdgt7=1;
            }
        }
        if (!gdgt10&&gadget_dump[i] == 0xa8c567fa) {
            if (gadget_dump[i+1] == 0xd65f03c0) {
                printf("ADDSP80 %llx\n", gadget_base+i*4);
                gdgt10=1;
            }
        }
        if (!gdgt8&&gadget_dump[i] == 0xd61f0000) {
            printf("JMPX0 %llx\n", gadget_base+i*4);
            gdgt8=1;
        }
        if (!gdgt6&&gadget_dump[i] == 0xd10103a2) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("SET_X2 %llx\n", gadget_base+i*4);
                gdgt6=1;
            }
        }
        if (!gdgt2&&gadget_dump[i] == 0xf9400008) {
            if (gadget_dump[i+1] == 0xf9000008) {
                if (gadget_dump[i+2] == 0xd65f03c0) {
                    printf("TAINT_X8 %llx\n", gadget_base+i*4);
                    gdgt2=1;
                }
            }
        }
        if (!gdgt11&&gadget_dump[i] == 0xf9400000) {
            if (gadget_dump[i+1] == 0xa8c17bfd) {
                if (gadget_dump[i+2] == 0xd65f03c0) {
                    printf("DEREFX0 %llx\n", gadget_base+i*4);
                    gdgt11=1;
                }
            }
        }
        if (!gdgt9&&gadget_dump[i] == 0x8b020000) {
            if (gadget_dump[i+1] == 0xa8c17bfd) {
                if (gadget_dump[i+2] == 0xd65f03c0) {
                    printf("ADDX0X2 %llx\n", gadget_base+i*4);
                    gdgt9=1;
                }
            }
        }
        if (gadget_dump[i] == 0xa9be4ff4) {
            if (gadget_dump[i+1] == 0xa9017bfd) {
                if (gadget_dump[i+2] == 0x910043fd) {
                    if (gadget_dump[i+3] == 0xaa0103f3) {
                        if (gadget_dump[i+4] == 0xf9400008) {
                            if (gadget_dump[i+5] == 0xf9406908) {
                                if (gadget_dump[i+6] == 0xd63f0100) {
                                    printf("STPL %llx\n", gadget_base+i*4);
                                    founddispatch++;
                                }
                            }
                        }
                    }
                }
            }
        }
        /*
         __TEXT_EXEC:__text:FFFFFFF0074E5C20 08 00 40 F9                 LDR             X8, [X0]
         __TEXT_EXEC:__text:FFFFFFF0074E5C24 07 3D 40 F9                 LDR             X7, [X8,#0x78]
         __TEXT_EXEC:__text:FFFFFFF0074E5C28 E0 00 1F D6                 BR              X7         */
        
        if (!moddispatch&&gadget_dump[i] == 0xf9400008) {
            if (gadget_dump[i+1] == 0xf9403d07) {
                if (gadget_dump[i+2] == 0xd61f00e0) {
                    printf("MMDISP %llx\n", gadget_base+i*4);
                    moddispatch++;
                }
            }
        }

        if (!foundsetl&&gadget_dump[i] == 0xa9422500) {
            if (gadget_dump[i+1] == 0xf9401901) {
                if (gadget_dump[i+2] == 0xf9400902) {
                    if (gadget_dump[i+3] == 0xb9401903) {
                        if (gadget_dump[i+4] == 0xd63f0120) {
                            printf("SETL %llx\n", gadget_base+i*4);
                            foundsetl++;
                        }
                    }
                }
            }
        }
        
        if (!foundsett&&gadget_dump[i] == 0xf9400908) {
            if (gadget_dump[i+1] == 0x910023e0) {
                if (gadget_dump[i+2] == 0xd63f0100) {
                    printf("SETT %llx\n", gadget_base+i*4);
                    foundsett++;
                }
            }
        }

        if (!gdgt15&&gadget_dump[i] == 0xd101c3a4) {
            if (gadget_dump[i+1] == 0xaa1303e0) {
                if (gadget_dump[i+2] == 0xaa1603e2) {
                    if (gadget_dump[i+3] == 0xd63f0100) {
                        printf("SETX4TR %llx\n", gadget_base+i*4);
                        gdgt15++;
                    }
                }
            }
        }

        if (!gdgt13&&gadget_dump[i] == 0x8b010000) {
            if (gadget_dump[i+1] == 0xa8c17bfd) {
                if (gadget_dump[i+2] == 0xd65f03c0) {
                    printf("ADDX0X1 %llx\n", gadget_base+i*4);
                    gdgt13++;
                }
            }
        }
        
        
        if (!set1imm&&gadget_dump[i] == 0xd103a3a1) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("SET1IMM %llx\n", gadget_base+i*4);
                set1imm++;
            }
        }
        
        if (!gdgt14&&gadget_dump[i] == 0x910003e0) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("MOVX0SP %llx\n", gadget_base+i*4);
                gdgt14++;
            }
        }
        
        
        if (!set020&&gadget_dump[i] == 0xaa0003f4) {
            if (gadget_dump[i+1] == 0xd63f0100) {
                printf("MOVX20X0 %llx\n", gadget_base+i*4);
                set020++;
            }
        }
        
        
        if ((gadget_dump[i] & 0xFFFFFC1F) == 0xD61F0000) {
            if (insn_is_adrp_64(gadget_dump[i-3]) && insn_adrp_rd_64(gadget_dump[i-3]) == 8 && insn_is_add_imm_64(gadget_dump[i-2]) && insn_is_ldr_imm_64(gadget_dump[i-1])) {
                if (adrof > insn_adrp_imm_64(gadget_dump[i-3])) {
                    adrof = insn_adrp_imm_64(gadget_dump[i-3]);
                    adrf = i;
                }
            }
        }
        
        if (gadget_dump[i] == 0xd5181040) {
            printf("CPACR %llx\n", i*4+gadget_base);
        }
    }
