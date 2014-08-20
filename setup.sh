#!/bin/bash

sysconfdir=/etc/sober
localstatedir=/var/sober

for dir in  $sysconfdir $localstatedir; do
    [ ! -d $dir ] && mkdir $dir
done

[ ! -f $sysconfdir/sober.cfg ] && cp sober.cfg $sysconfdir/
