/*
 *    _____                .__              ________   
 *   /     \ _____    ____ |  |__           \_____  \  
 *  /  \ /  \\__  \ _/ ___\|  |  \   ______  /   |   \ 
 * /    Y    \/ __ \\  \___|   Y  \ /_____/ /    |    \
 * \____|__  (____  /\___  >___|  /         \_______  /
 *         \/     \/     \/     \/                  \/ 
 * __________.__               .__        
 * \______   \  |  __ __  ____ |__| ____  
 *  |     ___/  | |  |  \/ ___\|  |/    \ 
 *  |    |   |  |_|  |  / /_/  >  |   |  \
 *  |____|   |____/____/\___  /|__|___|  /
 *                     /_____/         \/ 
 *
 * (c) 2011, fG! - reverser@put.as - http://reverse.put.as
 * 
 * -> You are free to use this code as long as you keep the original copyright <-
 *
 * An IDA plugin to display Mach-O header information
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * processheader.cpp
 *
 */

#include "processheader.h"

int process_loadcmds (char * loadcommands, int ncmds, uint64_t baseaddr, sample_info_t *si, unsigned int cputype)
{
    char buf[256];
    struct load_command *lc;
    char * loadcommands_ptr;
    int x;
	uint64_t addr;
	addr = baseaddr;
    for (x = 0; x < ncmds; x++)
    {
		loadcommands_ptr = loadcommands;
        lc = (struct load_command*)loadcommands_ptr;
#if DEBUG
        msg("Load command %d %x %d\n", x, lc->cmd, lc->cmdsize);
#endif
		SPACE();
        LOADSTRING("Load command", x);
        // some stuff grabbed from MachOview and otool source - less work ;-)
		// ugly stuff below, beware!
        switch (lc->cmd)
        {
            default:                      
            {
                set_cmt(addr, "???", 0);
                break;
            }
            case LC_SEGMENT:
            {
                                
                // process sections
                struct segment_command *cmd = (struct segment_command *)loadcommands_ptr;
				
                CONTENT_STRING_DWORD("      cmd", "LC_SEGMENT", addr, "-[ cmd LC_SEGMENT ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_STRING16_STRING("  segname", cmd->segname, addr+8, 16, "segname");
				CONTENT_HEX_DWORD("   vmaddr", cmd->vmaddr, addr+24,"vmaddr");
				CONTENT_HEX_DWORD("   vmsize", cmd->vmsize, addr+28, "vmsize");
				CONTENT_HEX_DWORD("  fileoff", cmd->fileoff, addr+32, "fileoff");
				CONTENT_HEX_DWORD(" filesize", cmd->filesize, addr+36, "filesize");
				CONTENT_HEX_DWORD("  maxprot", cmd->maxprot, addr+40, "maxprot");
				CONTENT_HEX_DWORD(" initprot", cmd->initprot, addr+44, "initprot");
				CONTENT_DEC_DWORD("   nsects", cmd->nsects, addr+48, "nsects");
				CONTENT_HEX_DWORD("    flags", cmd->flags, addr+52, "flags");

                int x;
                struct section *sct;
                int sectaddr = addr + sizeof(segment_command);
                loadcommands_ptr += sizeof(struct segment_command);
                for (x = 0; x < cmd->nsects; x++)
                {
                    sct = (struct section*)(loadcommands_ptr);
                    // hackish & ugly stuff!
                    SECTIONHEADER();					
					CONTENT_STRING16_STRING("  sectname", sct->sectname, sectaddr, 16, "sectname");
                    CONTENT_STRING16_STRING("   segname", sct->segname, sectaddr+16, 16, "segname");
					CONTENT_HEX_DWORD("      addr", sct->addr, sectaddr+32, "addr");
					CONTENT_HEX_DWORD("      size", sct->size, sectaddr+36, "size");
					CONTENT_HEX_DWORD("    offset", sct->offset, sectaddr+40, "offset");
					CONTENT_HEX_DWORD(" align 2^2", sct->align, sectaddr+44, "align 2^2");
					CONTENT_HEX_DWORD("    reloff", sct->reloff, sectaddr+48, "reloff");
					CONTENT_HEX_DWORD("    nreloc", sct->nreloc, sectaddr+52, "nreloc");
					CONTENT_HEX_DWORD("     flags", sct->flags, sectaddr+56, "flags");
					CONTENT_HEX_DWORD(" reserved1", sct->reserved1, sectaddr+60, "reserved1");
					CONTENT_HEX_DWORD(" reserved2", sct->reserved2, sectaddr+64, "reserved2");
                    // advance to next section
                    loadcommands_ptr += sizeof(struct section);
					sectaddr += sizeof(struct section);
                }                
                break;   
            }
            case LC_SYMTAB:
            {
				struct symtab_command *cmd = (struct symtab_command *)loadcommands_ptr;
                CONTENT_STRING_DWORD("      cmd", "LC_SYMTAB", addr, "-[ cmd LC_SYMTAB ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   symoff", cmd->symoff, addr+8, "symoff");
				CONTENT_DEC_DWORD("    nsyms", cmd->nsyms, addr+12, "nsyms");
				CONTENT_HEX_DWORD("   stroff", cmd->stroff, addr+16, "stroff");
				CONTENT_HEX_DWORD("  strsize", cmd->strsize, addr+20, "strsize");
                break;
            }
            case LC_SYMSEG:
            {
				struct symseg_command *cmd = (struct symseg_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_SYMSEG", addr, "-[ cmd LC_SYMSEG ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->offset, addr+8, "offset");
				CONTENT_HEX_DWORD("     size", cmd->size, addr+12, "size");
                break;
            }
            case LC_THREAD:
			case LC_UNIXTHREAD:
            {
				struct mythread_command
				{
					uint32_t	cmd;		/* LC_THREAD or  LC_UNIXTHREAD */
					uint32_t	cmdsize;	/* total size of this command */
					uint32_t	flavor;
					uint32_t	count;
				};
					
				struct mythread_command *cmd = (struct mythread_command *)loadcommands_ptr;
				switch (lc->cmd)
				{
					case LC_THREAD:
						CONTENT_STRING_DWORD("      cmd", "LC_THREAD", addr, "-[ cmd LC_THREAD ]-");
						break;
					case LC_UNIXTHREAD:
						CONTENT_STRING_DWORD("      cmd", "LC_UNIXTHREAD", addr, "-[ cmd LC_UNIXTHREAD ]-");
						break;
				}
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   flavor", cmd->flavor, addr+8, "flavor");
				CONTENT_HEX_DWORD("    count", cmd->count, addr+12, "count");
				// variables used to comment registers names	
				int z,w;
				
				switch (cputype)
				{
					case CPU_TYPE_X86:
					{
						switch (cmd->flavor)
						{
							case i386_THREAD_STATE:
								i386_thread_state_t *cpu;
								cpu = (i386_thread_state_t*)(loadcommands_ptr+sizeof(mythread_command));
								qsnprintf(buf, sizeof(buf),"          eax 0x%08x ebx    0x%08x ecx 0x%08x edx 0x%08x",
										  cpu->eax, cpu->ebx, cpu->ecx, cpu->edx);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"          edi 0x%08x esi    0x%08x ebp 0x%08x esp 0x%08x",
										  cpu->edi, cpu->esi, cpu->ebp, cpu->esp);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"          ss  0x%08x eflags 0x%08x eip 0x%08x cs  0x%08x",
										  cpu->ss, cpu->eflags, cpu->eip, cpu->cs);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"          ds  0x%08x es     0x%08x fs  0x%08x gs  0x%08x",
										  cpu->ds, cpu->es, cpu->fs, cpu->gs);
								PUSHBACK;
								static const char *myregisters[] = {"eax", "ebx", "ecx", "edx", "edi", "esi",
																	"ebp", "esp", "ss", "eflags", "eip","cs",
																	"ds", "es", "fs", "gs"};
								for (z = 0; z < 16; z++)
								{
									w = addr+16+z*4;
									doDwrd(w, 4);
									set_cmt(w, myregisters[z], 0);
								}
								break;
								// FIXME
							case i386_FLOAT_STATE:
								break;
							case i386_EXCEPTION_STATE:
								break;
							case x86_DEBUG_STATE32:
								break;
						}
					}	
						break;
					case CPU_TYPE_X86_64:
					{
						switch (cmd->flavor)
						{	
							case x86_THREAD_STATE64:
								x86_thread_state64_t *cpu;
								cpu = (x86_thread_state64_t*)(loadcommands_ptr+sizeof(mythread_command));
								qsnprintf(buf, sizeof(buf),"   rax  0x%016llx rbx 0x%016llx rcx  0x%016llx",
										  cpu->rax, cpu->rbx, cpu->rcx);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"   rdx  0x%016llx rdi 0x%016llx rsi  0x%016llx",
										  cpu->rdx, cpu->rdi, cpu->rsi);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"   rbp  0x%016llx rsp 0x%016llx r8   0x%016llx",
										  cpu->rbp, cpu->rsp, cpu->r8);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r9  0x%016llx r10 0x%016llx r11  0x%016llx",
										  cpu->r9, cpu->r10, cpu->r11);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"   r12  0x%016llx r13 0x%016llx r14  0x%016llx",
										  cpu->r12, cpu->r13, cpu->r14);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"   r15  0x%016llx rip 0x%016llx",
										  cpu->r15, cpu->rip);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"rflags  0x%016llx cs  0x%016llx fs   0x%016llx",
										  cpu->rflags, cpu->cs, cpu->fs);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    gs  0x%016llx",
										  cpu->gs);
								PUSHBACK;
								static const char *myregisters[] = {"rax", "rbx", "rcx", "rdx", "rdi", "rsi",
																	"rbp", "rsp", "r8", "r9", "r10", "r11",
																	"r12", "r13", "r14", "r15", "rip", "rflags",
																	"cs", "fs", "gs"};
								for (z = 0; z < 21; z++)
								{
									w = addr+16+z*8;
									doQwrd(w, 4);
									set_cmt(w, myregisters[z], 0);
								}
								break;
								// FIXME
							case x86_FLOAT_STATE64:
								break;
							case x86_EXCEPTION_STATE64:
								break;
							case x86_DEBUG_STATE64:
								break;
						}
						
						break;
					}
					case CPU_TYPE_POWERPC:
					{
						switch (cmd->flavor) 
						{
							case PPC_THREAD_STATE:
								ppc_thread_state_t *cpu;
								cpu = (ppc_thread_state_t*)(loadcommands_ptr+sizeof(mythread_command));
								qsnprintf(buf, sizeof(buf),"    r0  0x%08x r1  0x%08x r2  0x%08x r3   0x%08x r4   0x%08x",
										  cpu->__r0, cpu->__r1, cpu->__r2, cpu->__r3, cpu->__r4);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r5  0x%08x r6  0x%08x r7  0x%08x r8   0x%08x r9   0x%08x",
										  cpu->__r5, cpu->__r6, cpu->__r7, cpu->__r8, cpu->__r9);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r10 0x%08x r11 0x%08x r12 0x%08x r13  0x%08x r14  0x%08x",
										  cpu->__r10, cpu->__r11, cpu->__r12, cpu->__r13, cpu->__r14);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r15 0x%08x r16 0x%08x r17 0x%08x r18  0x%08x r19  0x%08x",
										  cpu->__r15, cpu->__r16, cpu->__r17, cpu->__r18, cpu->__r19);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r20 0x%08x r21 0x%08x r22 0x%08x r23  0x%08x r24  0x%08x",
										  cpu->__r20, cpu->__r21, cpu->__r22, cpu->__r23, cpu->__r24);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r25 0x%08x r26 0x%08x r27 0x%08x r28  0x%08x r29  0x%08x",
										  cpu->__r25, cpu->__r26, cpu->__r27, cpu->__r28, cpu->__r29);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    r30 0x%08x r31 0x%08x cr  0x%08x xer  0x%08x lr   0x%08x",
										  cpu->__r30, cpu->__r31, cpu->__cr, cpu->__xer, cpu->__lr);
								PUSHBACK;
								qsnprintf(buf, sizeof(buf),"    ctr 0x%08x mq  0x%08x vrsave 0x%08x srr0 0x%08x srr1 0x%08x",
										  cpu->__ctr, cpu->__mq, cpu->__vrsave, cpu->__srr0, cpu->__srr1);
								PUSHBACK;
								static const char *myregisters[] = {"r0", "r1", "r2", "r3", "r4", "r5",
																"r6", "r7", "r8", "r9", "r10","r11",
																"r12", "r13", "r14", "r15", "r16",
																"r17", "r18", "r19", "r20", "r21",
																"r22", "r23", "r24", "r25", "r26",
																"r27", "r28", "r29", "r30", "r31",
																"cr", "xer", "lr", "ctr", "mq", "vrsave",
																"srr0", "srr1"};
								for (z = 0; z < 40; z++)
								{
									w = addr+16+z*4;
									doDwrd(w, 4);
									set_cmt(w, myregisters[z], 0);
								}
								break;
								// FIXME
							case PPC_FLOAT_STATE:
								break;
							case PPC_EXCEPTION_STATE:
								break;
							case PPC_THREAD_STATE64:
								break;
						}
						break;
					}
					case CPU_TYPE_ARM:
					{
						arm_thread_state_t *cpu;
						cpu = (arm_thread_state_t*)(loadcommands_ptr+sizeof(mythread_command));
						qsnprintf(buf, sizeof(buf),"          r0  0x%08x r1     0x%08x r2  0x%08x r3  0x%08x",
								  cpu->r0, cpu->r1, cpu->r2, cpu->r3);
						PUSHBACK;
						qsnprintf(buf, sizeof(buf),"          r4  0x%08x r5     0x%08x r6  0x%08x r7  0x%08x",
								  cpu->r4, cpu->r5, cpu->r6, cpu->r7);
						PUSHBACK;
						qsnprintf(buf, sizeof(buf),"          r8  0x%08x r9     0x%08x r10 0x%08x r11 0x%08x",
								  cpu->r8, cpu->r9, cpu->r10, cpu->r11);
						PUSHBACK;
						qsnprintf(buf, sizeof(buf),"          r12 0x%08x r13    0x%08x r14 0x%08x r15 0x%08x",
								  cpu->r12, cpu->r13, cpu->r14, cpu->r15);
						PUSHBACK;
						qsnprintf(buf, sizeof(buf),"          r16 0x%08x", cpu->r16);
						PUSHBACK;
						static const char *myregisters[] = {"r0", "r1", "r2", "r3", "r4", "r5",
															"r6", "r7", "r8", "r9", "r10","r11",
															"r12", "r13", "r14", "r15", "r16"};
						for (z = 0; z < 17; z++)
						{
							w = addr+16+z*4;
							doDwrd(w, 4);
							set_cmt(w, myregisters[z], 0);
						}
						break;
					}
				}
                break;
            }
            case LC_LOADFVMLIB: // obsolete commands
			case LC_IDFVMLIB:
            {
				struct fvmlib_command *cmd = (struct fvmlib_command *)loadcommands_ptr;
				switch (lc->cmd)
				{
					case LC_LOADFVMLIB:
						CONTENT_STRING_DWORD("      cmd", "LC_LOADFVMLIB", addr, "-[ cmd LC_LOADFVMLIB ]-");
						break;
					case LC_IDFVMLIB:
						CONTENT_STRING_DWORD("      cmd", "LC_IDFVMLIB", addr, "-[ cmd LC_IDFVMLIB ]-");
						break;
				}
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				// FIXME - missing the fvmlib field - this is an obsolete command...
                break;    
            }
            case LC_IDENT: // obsolete command
            {
				struct ident_command *cmd = (struct ident_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_IDENT", addr, "-[ cmd LC_IDENT ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
                break;
            }
            case LC_FVMFILE: // internal command
            {
				struct fvmfile_command *cmd = (struct fvmfile_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("        cmd", "LC_FVMFILE", addr, "-[ cmd LC_FVMFILE ]-");
				CONTENT_HEX_DWORD("    cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_STRING_STRING("       name", (char*)cmd + cmd->name.offset, addr+8, cmd->cmdsize-sizeof(fvmfile_command), "name");
				CONTENT_HEX_DWORD("header addr", cmd->header_addr, addr+sizeof((char*)cmd + cmd->name.offset), "header addr");
                break;
            }
            case LC_PREPAGE: // ??
            {
				COMMENT_DWORD(addr, "cmd LC_PREPAGE");
                break;
            }
            case LC_DYSYMTAB:
            {
				struct dysymtab_command *cmd = (struct dysymtab_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("            cmd", "LC_DYSYMTAB", addr, "-[ cmd LC_DYSYMTAB ]-");
				CONTENT_HEX_DWORD("        cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("      ilocalsym", cmd->ilocalsym, addr+8, "ilocalsym");
				CONTENT_HEX_DWORD("      nlocalsym", cmd->nlocalsym, addr+12, "nlocalsym");
				CONTENT_HEX_DWORD("     iextdefsym", cmd->iextdefsym, addr+16, "iextdefsym");
				CONTENT_HEX_DWORD("     nextdefsym", cmd->nextdefsym, addr+20, "nextdefsym");
				CONTENT_HEX_DWORD("      iundefsym", cmd->iundefsym, addr+24, "iundefsym");
				CONTENT_HEX_DWORD("      nundefsym", cmd->nundefsym, addr+28, "nundefsym");
				CONTENT_HEX_DWORD("         tocoff", cmd->tocoff, addr+32, "tocoff");
				CONTENT_HEX_DWORD("           ntoc", cmd->ntoc, addr+36, "ntoc");
				CONTENT_HEX_DWORD("      modtaboff", cmd->modtaboff, addr+40, "modtaboff");
				CONTENT_HEX_DWORD("        nmodtab", cmd->nmodtab, addr+44, "nmodtab");
				CONTENT_HEX_DWORD("   extrefsymoff", cmd->extrefsymoff, addr+48, "extrefsymoff");
				CONTENT_HEX_DWORD("    nextrefsyms", cmd->nextrefsyms, addr+52, "nextrefsyms");
				CONTENT_HEX_DWORD(" indirectsymoff", cmd->indirectsymoff, addr+56, "indirectsymoff");
				CONTENT_HEX_DWORD("  nindirectsyms", cmd->nindirectsyms, addr+60, "nindirectsyms");
				CONTENT_HEX_DWORD("      extreloff", cmd->extreloff, addr+64, "extreloff");
				CONTENT_HEX_DWORD("        nextrel", cmd->nextrel, addr+68, "nextrel");
				CONTENT_HEX_DWORD("      locreloff", cmd->locreloff, addr+72, "locreloff");
				CONTENT_HEX_DWORD("        nlocrel", cmd->nlocrel, addr+76, "nlocrel");
                break;
            }
            case LC_LOAD_DYLIB:
            case LC_ID_DYLIB:
			case LC_LOAD_WEAK_DYLIB:
			case LC_REEXPORT_DYLIB:
            case LC_LAZY_LOAD_DYLIB:
            {
				struct dylib_command *cmd = (struct dylib_command *)loadcommands_ptr;
				switch (lc->cmd)
				{
					case LC_LOAD_DYLIB:
						CONTENT_STRING_DWORD("      cmd", "LC_LOAD_DYLIB", addr, "-[ cmd LC_LOAD_DYLIB ]-");
						break;
					case LC_ID_DYLIB:
						CONTENT_STRING_DWORD("      cmd","LC_ID_DYLIB", addr, "-[ cmd LC_ID_DYLIB ]-");
						break;
					case LC_LOAD_WEAK_DYLIB:
						CONTENT_STRING_DWORD("      cmd","LC_LOAD_WEAK_DYLIB", addr, "-[ cmd LC_LOAD_WEAK_DYLIB ]-");	
						break;
					case LC_REEXPORT_DYLIB:
						CONTENT_STRING_DWORD("      cmd","LC_REEXPORT_DYLIB", addr, "-[ cmd LC_REEXPORT_DYLIB ]-");
						break;
					case LC_LAZY_LOAD_DYLIB:
						CONTENT_STRING_DWORD("      cmd","LC_LAZY_LOAD_DYLIB", addr, "-[ cmd LC_LAZY_LOAD_DYLIB ]-");
						break;
				}			
				CONTENT_HEX_DWORD("      cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("       offset", cmd->dylib.name.offset, addr+8, "offset");
				CONTENT_STRING_STRING("         name", (char*)cmd + cmd->dylib.name.offset, addr+cmd->dylib.name.offset, cmd->cmdsize-sizeof(dylib_command), "name");

				time_t time = cmd->dylib.timestamp;
				CONTENT_STRING_STRING("    timestamp", ctime(&time), addr+12, sizeof(ctime(&time)), "timestamp");
				qsnprintf(buf, sizeof(buf),"      current version %u.%u.%u", cmd->dylib.current_version >> 16,
																			(cmd->dylib.current_version >> 8) & 0xff,
																			cmd->dylib.current_version & 0xff);
				PUSHBACK;
				COMMENT_DWORD(addr+16, "current version");
				qsnprintf(buf, sizeof(buf),"compatibility version %u.%u.%u", cmd->dylib.compatibility_version >> 16,
																			(cmd->dylib.compatibility_version >> 8) & 0xff,
																			cmd->dylib.compatibility_version & 0xff);
				PUSHBACK;
				COMMENT_DWORD(addr+20, "compatibility version");
				break;
			}				
            case LC_LOAD_DYLINKER:
			case LC_ID_DYLINKER:
			{
				struct dylinker_command *cmd = (struct dylinker_command *)loadcommands_ptr;
				switch (lc->cmd)
				{
					case LC_LOAD_DYLINKER:
						CONTENT_STRING_DWORD("          cmd", "LC_LOAD_DYLINKER", addr, "-[ cmd LC_LOAD_DYLINKER ]-");
						break;
					case LC_ID_DYLINKER:
						CONTENT_STRING_DWORD("          cmd", "LC_ID_DYLINKER", addr, "-[ cmd LC_ID_DYLINKER ]-");
						break;
				}
				CONTENT_HEX_DWORD("      cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("       offset", cmd->name.offset, addr+8, "offset");
				CONTENT_STRING_STRING("         name", (char*)cmd + cmd->name.offset, addr+12, cmd->cmdsize-sizeof(dylinker_command), "name");
				break;
			}
            case LC_PREBOUND_DYLIB:
			{
				struct prebound_dylib_command *cmd = (struct prebound_dylib_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_PREBOUND_DYLIB", addr, "-[ cmd LC_PREBOUND_DYLIB ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->name.offset, addr+8, "offset");
				CONTENT_STRING_STRING("     name", (char*)cmd + cmd->name.offset, addr+12, cmd->cmdsize-sizeof(prebound_dylib_command), "name");
				CONTENT_DEC_DWORD(" nmodules", cmd->nmodules, addr+16, "nmodules");
				// FIXME: missing linked_modules
				break;
			}
            case LC_ROUTINES:
			{
				struct routines_command *cmd = (struct routines_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("         cmd", "LC_ROUTINES", addr, "-[ cmd LC_ROUTINES ]-");
				CONTENT_HEX_DWORD("     cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("init_address", cmd->init_address, addr+8, "init_address");
				CONTENT_HEX_DWORD(" init_module", cmd->init_module, addr+12, "init_module");
				CONTENT_HEX_DWORD("   reserved1", cmd->reserved1, addr+16, "reserved1");
				CONTENT_HEX_DWORD("   reserved1", cmd->reserved2, addr+20, "reserved2");
				CONTENT_HEX_DWORD("   reserved1", cmd->reserved3, addr+24, "reserved3");
				CONTENT_HEX_DWORD("   reserved1", cmd->reserved4, addr+30, "reserved4");
				CONTENT_HEX_DWORD("   reserved1", cmd->reserved5, addr+34, "reserved5");
				CONTENT_HEX_DWORD("   reserved1", cmd->reserved6, addr+38, "reserved6");
				break;
			}
            case LC_SUB_FRAMEWORK:
			{
				struct sub_framework_command *cmd = (struct sub_framework_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_SUB_FRAMEWORK", addr, "-[ cmd LC_SUB_FRAMEWORK ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->umbrella.offset, addr+8, "offset");
				CONTENT_STRING_STRING("     name", (char*)cmd + cmd->umbrella.offset, addr+12, cmd->cmdsize-sizeof(sub_framework_command), "name");
				break;
			}
            case LC_SUB_UMBRELLA:
			{
				struct sub_umbrella_command *cmd = (struct sub_umbrella_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_SUB_UMBRELLA", addr, "-[ cmd LC_SUB_UMBRELLA ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->sub_umbrella.offset, addr+8, "offset");
				CONTENT_STRING_STRING("     name", (char*)cmd + cmd->sub_umbrella.offset, addr+12, cmd->cmdsize-sizeof(sub_umbrella_command), "name");
				break;
			}
            case LC_SUB_CLIENT:
			{
				struct sub_client_command *cmd = (struct sub_client_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_SUB_CLIENT", addr, "-[ cmd LC_SUB_CLIENT ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->client.offset, addr+8, "offset");
				CONTENT_STRING_STRING("     name", (char*)cmd + cmd->client.offset, addr+12, cmd->cmdsize-sizeof(sub_client_command), "name");
				break;
			}
            case LC_SUB_LIBRARY:
			{
				struct sub_library_command *cmd = (struct sub_library_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_SUB_LIBRARY", addr, "-[ cmd LC_SUB_LIBRARY ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->sub_library.offset, addr+8, "offset");
				CONTENT_STRING_STRING("     name", (char*)cmd + cmd->sub_library.offset, addr+12, cmd->cmdsize-sizeof(sub_library_command), "name");
				break;
			}
            case LC_TWOLEVEL_HINTS:
			{
				struct twolevel_hints_command *cmd = (struct twolevel_hints_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_TWOLEVEL_HINTS", addr, "-[ cmd LC_TWOLEVEL_HINTS ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->offset, addr+8, "offset");
				CONTENT_HEX_DWORD("   nhints", cmd->nhints, addr+12, "nhints");
				break;
			}
            case LC_PREBIND_CKSUM:
			{
				struct prebind_cksum_command *cmd = (struct prebind_cksum_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_PREBIND_CKSUM", addr, "-[ cmd LC_PREBIND_CKSUM ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("    cksum", cmd->cksum, addr+8, "cksum");
				break;
			}
            case LC_SEGMENT_64:
			{
				// process sections
                struct segment_command_64 *cmd = (struct segment_command_64 *)loadcommands_ptr;
                
				CONTENT_STRING_DWORD("      cmd", "LC_SEGMENT_64", addr, "-[ cmd LC_SEGMENT_64 ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_STRING16_STRING("  segname", cmd->segname, addr+8, 16, "segname");
				CONTENT_HEX64_DWORD("   vmaddr", cmd->vmaddr, addr+24,"vmaddr");
				CONTENT_HEX64_DWORD("   vmsize", cmd->vmsize, addr+32, "vmsize");
				CONTENT_HEX64_DWORD("  fileoff", cmd->fileoff, addr+40, "fileoff");
				CONTENT_HEX64_DWORD(" filesize", cmd->filesize, addr+48, "filesize");
				CONTENT_HEX_DWORD("  maxprot", cmd->maxprot, addr+52, "maxprot");
				CONTENT_HEX_DWORD(" initprot", cmd->initprot, addr+56, "initprot");
				CONTENT_DEC_DWORD("   nsects", cmd->nsects, addr+60, "nsects");
				CONTENT_HEX_DWORD("    flags", cmd->flags, addr+64, "flags");
								
                int x;
                struct section_64 *sct;
                int sectaddr = addr + sizeof(segment_command_64);
                loadcommands_ptr += sizeof(struct segment_command_64);
                for (x = 0; x < cmd->nsects; x++)
                {
					
                    sct = (struct section_64*)(loadcommands_ptr);
                    // hackish & ugly stuff!
                    SECTIONHEADER();
					CONTENT_STRING16_STRING("  sectname", sct->sectname, sectaddr, 16, "sectname");
                    CONTENT_STRING16_STRING("   segname", sct->segname, sectaddr+16, 16, "segname");
					CONTENT_HEX64_DWORD("      addr", sct->addr, sectaddr+32, "addr");
					CONTENT_HEX64_DWORD("      size", sct->size, sectaddr+40, "size");
					CONTENT_HEX_DWORD("    offset", sct->offset, sectaddr+48, "offset");
					CONTENT_HEX_DWORD(" align 2^2", sct->align, sectaddr+52, "align 2^2");
					CONTENT_HEX_DWORD("    reloff", sct->reloff, sectaddr+56, "reloff");
					CONTENT_HEX_DWORD("    nreloc", sct->nreloc, sectaddr+60, "nreloc");
					CONTENT_HEX_DWORD("     flags", sct->flags, sectaddr+64, "flags");
					CONTENT_HEX_DWORD(" reserved1", sct->reserved1, sectaddr+68, "reserved1");
					CONTENT_HEX_DWORD(" reserved2", sct->reserved2, sectaddr+72, "reserved2");
					
					// advance to next section
                    loadcommands_ptr += sizeof(struct section_64);
					sectaddr += sizeof(struct section_64);
                }
				break;
			}
            case LC_ROUTINES_64:
			{
				struct routines_command_64 *cmd = (struct routines_command_64 *)loadcommands_ptr;
				CONTENT_STRING_DWORD("         cmd", "LC_ROUTINES_64", addr, "-[ cmd LC_ROUTINES_64 ]-");
				CONTENT_HEX_DWORD("     cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX64_DWORD("init_address", cmd->init_address, addr+8, "init_address");
				CONTENT_HEX64_DWORD(" init_module", cmd->init_module, addr+16, "init_module");
				CONTENT_HEX64_DWORD("   reserved1", cmd->reserved1, addr+24, "reserved1");
				CONTENT_HEX64_DWORD("   reserved1", cmd->reserved2, addr+32, "reserved2");
				CONTENT_HEX64_DWORD("   reserved1", cmd->reserved3, addr+40, "reserved3");
				CONTENT_HEX64_DWORD("   reserved1", cmd->reserved4, addr+48, "reserved4");
				CONTENT_HEX64_DWORD("   reserved1", cmd->reserved5, addr+56, "reserved5");
				CONTENT_HEX64_DWORD("   reserved1", cmd->reserved6, addr+64, "reserved6");
				break;
			}
            case LC_UUID:
			{
                struct uuid_command *cmd = (struct uuid_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_UUID", addr, "-[ cmd LC_UUID ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				COMMENT_DWORD(addr+8, "uuid");
				COMMENT_DWORD(addr+12, "uuid");
				COMMENT_DWORD(addr+16, "uuid");
				COMMENT_DWORD(addr+20, "uuid");
				qsnprintf(buf, sizeof(buf), "     uuid %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", 
						  (unsigned int)cmd->uuid[0],  (unsigned int)cmd->uuid[1],
						  (unsigned int)cmd->uuid[2],  (unsigned int)cmd->uuid[3],
						  (unsigned int)cmd->uuid[4],  (unsigned int)cmd->uuid[5],
						  (unsigned int)cmd->uuid[6],  (unsigned int)cmd->uuid[7],
						  (unsigned int)cmd->uuid[8],  (unsigned int)cmd->uuid[9],
						  (unsigned int)cmd->uuid[10], (unsigned int)cmd->uuid[11],
						  (unsigned int)cmd->uuid[12], (unsigned int)cmd->uuid[13],
						  (unsigned int)cmd->uuid[14], (unsigned int)cmd->uuid[15]);
				PUSHBACK;
				break;

			}
            case LC_RPATH:
			{
				struct rpath_command *cmd = (struct rpath_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_RPATH", addr, "-[ cmd LC_RPATH ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("   offset", cmd->path.offset, addr+8, "offset");
				CONTENT_STRING_STRING("     name", (char*)cmd + cmd->path.offset, addr+12, cmd->cmdsize-sizeof(rpath_command), "name");
				break;
			}
            case LC_CODE_SIGNATURE:
			case LC_SEGMENT_SPLIT_INFO:
			case LC_FUNCTION_STARTS:
			{
				struct linkedit_data_command *cmd = (struct linkedit_data_command *)loadcommands_ptr;
				switch (lc->cmd)
				{
					case LC_CODE_SIGNATURE:
						CONTENT_STRING_DWORD("      cmd", "LC_CODE_SIGNATURE", addr, "-[ cmd LC_CODE_SIGNATURE ]-");
						break;
					case LC_SEGMENT_SPLIT_INFO:
						CONTENT_STRING_DWORD("      cmd", "LC_SEGMENT_SPLIT_INFO", addr, "-[ cmd LC_SEGMENT_SPLIT_INFO ]-");
						break;
					case LC_FUNCTION_STARTS:
						CONTENT_STRING_DWORD("      cmd", "LC_FUNCTION_STARTS", addr, "-[ cmd LC_FUNCTION_STARTS ]-");
						break;
				}
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("  dataoff", cmd->dataoff, addr+8, "dataoff");
				CONTENT_HEX_DWORD(" datasize", cmd->datasize, addr+12, "datasize");
				break;
			}
            case LC_ENCRYPTION_INFO:
			{
				struct encryption_info_command *cmd = (struct encryption_info_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_ENCRYPTION_INFO", addr, "-[ cmd LC_ENCRYPTION_INFO ]-");
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD(" cryptoff", cmd->cryptoff, addr+8, "cryptoff");
				CONTENT_HEX_DWORD("cryptsize", cmd->cryptsize, addr+12, "cryptsize");
				CONTENT_HEX_DWORD("  cryptid", cmd->cryptid, addr+16, "cryptid");
				break;
			}
            case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
			{
				struct dyld_info_command *cmd = (struct dyld_info_command *)loadcommands_ptr;
				switch (lc->cmd) 
				{
					case LC_DYLD_INFO:
						CONTENT_STRING_DWORD("           cmd", "LC_DYLD_INFO", addr, "-[ cmd LC_DYLD_INFO ]-");
						break;
					case LC_DYLD_INFO_ONLY:
						CONTENT_STRING_DWORD("           cmd", "LC_DYLD_INFO_ONLY", addr, "-[ cmd LC_DYLD_INFO_ONLY ]-");
						break;
				}
				CONTENT_HEX_DWORD("       cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("    rebase_off", cmd->rebase_off, addr+8, "rebase_off");
				CONTENT_HEX_DWORD("   rebase_size", cmd->rebase_size, addr+12, "rebase_size");
				CONTENT_HEX_DWORD("      bind_off", cmd->bind_off, addr+16, "bind_off");
				CONTENT_HEX_DWORD("     bind_size", cmd->bind_size, addr+20, "bind_size");
				CONTENT_HEX_DWORD("     bind_size", cmd->bind_size, addr+24, "bind_size");
				CONTENT_HEX_DWORD(" weak_bind_off", cmd->weak_bind_off, addr+28, "weak_bind_off");
				CONTENT_HEX_DWORD("weak_bind_size", cmd->weak_bind_size, addr+32, "weak_bind_size");
				CONTENT_HEX_DWORD(" lazy_bind_off", cmd->lazy_bind_off, addr+36, "lazy_bind_off");
				CONTENT_HEX_DWORD("lazy_bind_size", cmd->lazy_bind_size, addr+40, "lazy_bind_size");
				CONTENT_HEX_DWORD("    export_off", cmd->export_off, addr+44, "export_off");
				CONTENT_HEX_DWORD("   export_size", cmd->export_size, addr+48, "export_size");
				break;
			}            
            case LC_LOAD_UPWARD_DYLIB: // treat this just like LC_LOAD_DYLIB
			{
				struct dylib_command *cmd = (struct dylib_command *)loadcommands_ptr;
				CONTENT_STRING_DWORD("      cmd", "LC_LOAD_UPWARD_DYLIB", addr, "-[ cmd LC_LOAD_UPWARD_DYLIB ]-");
				CONTENT_HEX_DWORD("       cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("       offset", cmd->dylib.name.offset, addr+8, "offset");
				CONTENT_STRING_STRING("         name", (char*)cmd + cmd->dylib.name.offset, addr+cmd->dylib.name.offset, cmd->cmdsize-sizeof(dylib_command), "name");
				
				time_t time = cmd->dylib.timestamp;
				CONTENT_STRING_STRING("    timestamp", ctime(&time), addr+12, sizeof(ctime(&time)), "timestamp");
				qsnprintf(buf, sizeof(buf),"      current version %u.%u.%u", cmd->dylib.current_version >> 16,
						  (cmd->dylib.current_version >> 8) & 0xff,
						  cmd->dylib.current_version & 0xff);
				PUSHBACK;
				COMMENT_DWORD(addr+16, "current version");
				qsnprintf(buf, sizeof(buf),"compatibility version %u.%u.%u", cmd->dylib.compatibility_version >> 16,
						  (cmd->dylib.compatibility_version >> 8) & 0xff,
						  cmd->dylib.compatibility_version & 0xff);
				PUSHBACK;
				COMMENT_DWORD(addr+20, "compatibility version");
				
				break;
			}
            case LC_VERSION_MIN_MACOSX:
			case LC_VERSION_MIN_IPHONEOS:
			{
				struct version_min_command *cmd = (struct version_min_command *)loadcommands_ptr;
				switch (lc->cmd) 
				{
					case LC_VERSION_MIN_MACOSX:
						CONTENT_STRING_DWORD("      cmd", "LC_VERSION_MIN_MACOSX", addr, "-[ cmd LC_VERSION_MIN_MACOSX ]-");
						break;
					case LC_VERSION_MIN_IPHONEOS:
						CONTENT_STRING_DWORD("      cmd", "LC_VERSION_MIN_IPHONEOS", addr, "-[ cmd LC_VERSION_MIN_IPHONEOS ]-");
						break;
				}
				CONTENT_HEX_DWORD("  cmdsize", cmd->cmdsize, addr+4, "cmdsize");
				CONTENT_HEX_DWORD("  version", cmd->version, addr+8, "version");
				CONTENT_HEX_DWORD(" reserved", cmd->reserved, addr+12, "reserved");
				break;
			}
        }
        loadcommands += lc->cmdsize;
		addr += lc->cmdsize;
    }
    return(0);
}
