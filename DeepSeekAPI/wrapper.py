#!/usr/bin/env python3

'''
DeepSeek API - Provides an unofficial API for DeepSeek by reverse-engineering its web interface.
Copyright (C) 2025 smkttl

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

from .DeepSeekChat import DeepSeekChat
from enum import Enum
import subprocess
import sys
import io
class IOMethods(Enum):
    PRINT=1
    RETURN=2
    STREAMDOWN=3
def DeepSeekChatExample(DS_SESSION_ID,AUTHORIZATION_TOKEN,message,mode,thinking_enabled=False,search_enabled=False,model_type="default"):
    if mode==IOMethods.STREAMDOWN:
        proc=subprocess.Popen(
            [
                sys.executable,
                '-c',
                f"from DeepSeekAPI import DeepSeekChat; DeepSeekChat({repr(DS_SESSION_ID)},{repr(AUTHORIZATION_TOKEN)}).send_message({repr(message)},True,{thinking_enabled},{search_enabled},{repr(model_type)})"
            ],
            stdout=subprocess.PIPE,
            text=False
        )
        from .streamdown import init,emit
        init()
        emit(proc.stdout)
        return
    else:
        ret=DeepSeekChat(DS_SESSION_ID,AUTHORIZATION_TOKEN).send_message(message,mode==IOMethods.PRINT,thinking_enabled,search_enabled,model_type)
        if mode==IOMethods.PRINT:
            return
        return ret
