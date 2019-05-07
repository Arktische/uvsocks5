## uvsocks5
a lightweight socks5 proxy server implemention powered by libuv1.40.0. (Only upport `CONNECT` command and `AUTH_NONE` so far).
### platform
notice: still **on developing**
|  platform   | compiler  | supported |
|  ----  | ----  | ---- |
| windows  | mingw-w64 gcc only| yes |
| linux  | gcc / clang | yes |
### build
cmake is required for building. Then execute the command below.
```bash
git clone https://github.com/Arktische/uvsocks5.git
cd uvsocks5
mkdir build && cd build
cmake ../ -DCMAKE_BUILD_TYPE=Release
make -j4
```