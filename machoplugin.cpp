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
 *  v0.3
 *
 * (c) 2011, fG! - reverser@put.as - http://reverse.put.as
 * 
 * -> You are free to use this code as long as you keep the original copyright <-
 *
 * An IDA plugin to display Mach-O header information
 *
 * GUI code based on Custom viewer sample plugin by Ilfak Guilfanov.
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
 * machoplugin.cpp
 *
 */

#include "machoplugin.h"

#define DEBUG 0

int counter = 0;

int IDAP_init(void)
{
    if (inf.filetype != f_MACHO)
    {
		// if it's not mach-o binary then plugin is unavailable
		msg("[macho plugin] Executable format must be Mach-O!");
		return PLUGIN_SKIP;
    }   
    return PLUGIN_KEEP;
}

void IDAP_term(void) 
{
    return;
}

void IDAP_run(int arg)
{
/* 
    extern plugin_t PLUGIN;
#ifdef __MAC__
	PLUGIN.flags |= PLUGIN_UNL;
#endif
*/
	// workaround to the form problems - to be removed when fixed
	char mycaption[17];
	qsnprintf(mycaption, 17, "Mach-O Header %2d", counter);
	counter++;
	
    HWND hwnd = NULL;
    // try to create the custom view
    TForm *form = create_tform(mycaption, &hwnd);
    // if creation failed, maybe it already exists
	// this doesn't seem to work with the new QT GUI, only with the old one
    if ( hwnd == NULL )
    {
        warning("Could not create custom view window\n"
                "perhaps it is open?\n"
                "Switching to it.");
        // search for the form with this specific caption
        form = find_tform("Mach-O Header");
        // if found then activate it
        if ( form != NULL )
            switchto_tform(form, true);
        return;
    }
    // allocate block to hold info about our sample view
    sample_info_t *si = new sample_info_t(form);

	// retrieve the address of the header
	// IDA stores this at segment called HEADER so we can easily retrieve
	// for 32 and 64 bits binaries
	segment_t *textSeg = get_segm_by_name("HEADER");
#if DEBUG
	msg("Text segment is at %llx\n", (long long)textSeg->startEA);
#endif
	// IDA doesn't display the fat header so we always start by reading
	// the mach_header
    // allocate space to the header
#ifdef __EA64__
	int mach_header_size = sizeof(struct mach_header_64);
	struct mach_header_64 *mh; /* mach header */
	mh = (struct mach_header_64 *)qalloc(mach_header_size);
#else
	int mach_header_size = sizeof(struct mach_header);
	struct mach_header *mh; /* mach header */
	mh = (struct mach_header *)qalloc(mach_header_size);
#endif
    // read the mach_header
	get_many_bytes(textSeg->startEA, mh, mach_header_size);

	// we can start to comment out the fields
	COMMENT_DWORD(textSeg->startEA, "magic");
	COMMENT_DWORD(textSeg->startEA+4, "cputype");
	COMMENT_DWORD(textSeg->startEA+8, "cpusubtype");
	COMMENT_DWORD(textSeg->startEA+12, "filetype");
	COMMENT_DWORD(textSeg->startEA+16, "ncmds");
	COMMENT_DWORD(textSeg->startEA+20, "sizeofcmds");
	COMMENT_DWORD(textSeg->startEA+24, "flags");
#ifdef __EA64__
	COMMENT_DWORD(textSeg->startEA+28, "reserved");
#endif

    // we can read the next block of information, the load commands
    // from mach_header structure we have two fields, ncmds and sizeofcmds
    char * loadcommands = (char *)qalloc(mh->sizeofcmds);
    get_many_bytes(textSeg->startEA+mach_header_size, loadcommands, mh->sizeofcmds);
    
    process_loadcmds(loadcommands, mh->ncmds, textSeg->startEA+mach_header_size, si, mh->cputype);
    
    // prepare the data to display. we could prepare it on the fly too.
    // but for that we have to use our own custom place_t class decendant.
    //si->sv.push_back(simpleline_t("Helloooooooo\n"));
    // create two place_t objects: for the minimal and maximal locations
    simpleline_place_t s1;
    simpleline_place_t s2(si->sv.size()-1);

    // create a custom viewer
    si->cv = create_custom_viewer("", (TWinControl *)form, &s1, &s2, &s1, 0, &si->sv);
    
    // finally display the form on the screen
    open_tform(form, FORM_TAB|FORM_MENU|FORM_RESTORE);

	qfree(mh);
	return;
}

char IDAP_comment[]	= "Plugin to display Mach-O Headers";
char IDAP_help[]	= "Mach-O Plugin";
char IDAP_name[]	= "Display Mach-O Header";
char IDAP_hotkey[]	= "Alt-X";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,
	IDAP_init,
	IDAP_term,
	IDAP_run,
	IDAP_comment,
	IDAP_help,
	IDAP_name,
	IDAP_hotkey
};
