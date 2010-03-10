/* LIBUSB-WIN32, Generic Windows USB Library
 * Copyright (c) 2002-2005 Stephan Meyer <ste_meyer@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "libusb_driver.h"
#include <stdio.h>
#include <stdarg.h>

int debug_level = LIBUSB0_DEBUG_MSG;

void DEBUG_PRINT_NL()
{
#ifdef DBG
  if(debug_level >= LIBUSB0_DEBUG_MSG) 
    DbgPrint(("\n"));
#endif
}

void DEBUG_SET_LEVEL(int level)
{
#ifdef DBG
  debug_level = level;
#endif
}

void DEBUG_MESSAGE(const char *format, ...)
{
#ifdef DBG
  
  char tmp[256];
  
  if(debug_level >= LIBUSB0_DEBUG_MSG)
    {
      va_list args;
      va_start(args, format);
      _vsnprintf(tmp, sizeof(tmp) - 1, format, args);
      va_end(args);

      DbgPrint("LIBUSB-DRIVER - %s", tmp);
    }
#endif
}

void DEBUG_ERROR(const char *format, ...)
{
#ifdef DBG
  
  char tmp[256];
  
  if(debug_level >= LIBUSB0_DEBUG_ERR)
    {
      va_list args;
      va_start(args, format);
      _vsnprintf(tmp, sizeof(tmp) - 1, format, args);
      va_end(args);

      DbgPrint("LIBUSB-DRIVER - %s", tmp);
    }
#endif
}
