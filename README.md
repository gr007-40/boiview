# boiview

A simple .boi image file viewer on top of the sokol headers.
Created for UDCTF 2023

Sokol: https://github.com/floooh/sokol

## Build:

```bash
> mkdir build
> cd build

> cmake ..
> cmake --build .
```

## Release:

```bash
> cmake -DCMAKE_BUILD_TYPE=MinSizeRel ..
> cmake --build .
```

NOTE: on Linux you'll also need to install the 'usual' dev-packages needed for X11+GL development. On OpenBSD, it is assumed you have X installed.

## Run:

```bash
> ./boiview file=../images/flag.boi
```
