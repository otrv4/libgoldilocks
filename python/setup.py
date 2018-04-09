#!/usr/bin/env python
#
# Copyright 2017 John-Mark Gurney.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#

from distutils.command.build import build
from distutils.core import setup

import os

class my_build(build):
    def run(self):
        build.run(self)
        if not self.dry_run:
            os.spawnlp(os.P_WAIT, 'sh', 'sh', '-c', 'cd .. && gmake lib')
            self.copy_file(os.path.join('..', 'build', 'lib', 'libgoldilocks.so'), os.path.join(self.build_lib, 'edgold'))

cmdclass = {}
cmdclass['build'] = my_build

setup(name='edgold',
      version='0.1',
      description='The Ed ECC Goldilocks Python wrapper',
      author='John-Mark Gurney',
      author_email='jmg@funkthat.com',
      #url='',
      cmdclass=cmdclass,
      packages=['edgold', ],
     )
