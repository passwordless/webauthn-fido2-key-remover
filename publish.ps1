dotnet publish ./src/ -o ./dist/ -r win-x86 /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true --self-contained true -p:PublishReadyToRun=true -c Release