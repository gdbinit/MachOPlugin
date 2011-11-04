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
 * machoplugin.h
 *
 */

// IDA SDK includes
#include <ida.hpp> 
#include <idp.hpp> 
#include <loader.hpp>
#include <bytes.hpp>
#include <kernwin.hpp>

// OS X includes
#ifdef __MAC__
	#include <mach-o/loader.h>
#else
	#include "loader.h"
#endif


#include "mymacros.h"

// Structure to keep all information about the our sample view
struct sample_info_t
{
    TForm *form;
    TCustomControl *cv;
    strvec_t sv;
    sample_info_t(TForm *f) : form(f), cv(NULL) {}
};

extern int process_loadcmds (char *, int, uint64_t, sample_info_t *, unsigned int);
