#!/bin/bash
Scripts/cleanBuild.sh
if [ ! -d "build" ]; then
  mkdir build
fi
if [ ! -d "bin" ]; then
  mkdir bin
fi
if [ ! -d "lib" ]; then
  mkdir lib
fi
cd ./build
rm -rf ./*
cmake ..
make -j2
cd ..
cd ./bin
mkdir Containers Recipes
cd ..
cp config.json ./bin
cp -r ./key ./bin/
cp Scripts/cleanRunTime.sh ./bin
