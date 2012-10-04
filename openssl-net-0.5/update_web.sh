#!/bin/sh

rsync -avzP README INSTALL COPYING LICENSE CHANGES TODO web/ friedric,openssl-net@web.sourceforge.net:htdocs/
