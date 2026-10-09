# GBOffline - in-process virtual server for Gunship Battle

No real server, no local server process. A dylib inside the game answers requests to the dead
Joycity/Joyple hosts from local files.

## Update v3 (current step)
Found: __S3E_DATA (vtables, constants, probably the key) is compressed in the file and only unpacked in
memory, so static analysis can't see it. v3 dumps it (plus __S3E_META and __DATA) 30 s after launch to
Documents/gb_dump__S3E_DATA.bin, gb_dump__S3E_META.bin, gb_dump__DATA.bin and gb_dump_info.txt.
Send those 4 files (about 3 MB) together with gb_capture.log. Also: resource files in text/ and csv/ are
plain XOR 0x33 (decoded; the update message is text ID 1072).

## Update v2: find the encryption key
The first capture showed the lobby wraps every request as {"PayLoad":"<base64 AES>"} and expects the
reply wrapped the same way, so a plain JSON reply makes the game think it needs an update.
v2 adds (1) a CommonCrypto trace and (2) a one-time scan of the game's memory that tests every
candidate against your captured payload. Build with gb_keyscan.h in the same folder as GBOffline.m,
copy gb_routes.json + stubs/ INTO the .app too (the last log showed "routes: 0": no config was found),
launch, wait ~5 minutes on the first connect, then send me Documents/gb_capture.log again.
Look for lines starting with [KEYSCAN] and [crypto].

## Build
    xcrun -sdk iphoneos clang -arch arm64 -dynamiclib -fobjc-arc -framework Foundation \
        -miphoneos-version-min=10.0 -o GBOffline.dylib GBOffline.m
(The binary you sent is arm64, so arm64 only.)

## Install
1. Put GBOffline.dylib, gb_routes.json and the stubs/ folder inside `GUNSHIP BATTLE.app`
   (or inject the dylib with Sideloadly / insert_dylib, which adds the LC_LOAD_DYLIB for you).
2. Re-sign and install as usual.
3. Optional: later you can drop an edited gb_routes.json + stubs/ into the app's Documents folder;
   Documents overrides the bundle, so you don't have to re-sign to iterate.

## Workflow (important)
1. First run: the draft stubs (guessed from field names in the binary, see KEYS.md) answer matching calls; everything else gets {"result":0,"ErrorCode":0}, and all of it is logged.
2. Pull `Documents/gb_capture.log`. Each line shows layer (nsurl / sock / dns), method, host+path,
   request body, and whether a ROUTE or the DEFAULT answered.
3. For each endpoint the game hits, add a route in gb_routes.json and write the response file in stubs/.
   Use `body_contains` to separate calls that share one URL (e.g. the lobby command name).
4. Repeat until the game gets past the connect/login/load screens.

## Known limits
- Untested on-device (no iOS toolchain/device in my sandbox). Treat as a working skeleton.
- Response formats are NOT known yet; they come from the capture log / reversing the client's parsers.
- TLS raw-socket traffic (port 443) cannot be served by the plaintext responder; HTTPS made through
  NSURLConnection/NSURLSession is fine (intercepted before TLS).
- Chunked request bodies are not parsed on the socket layer (logged as a warning).
