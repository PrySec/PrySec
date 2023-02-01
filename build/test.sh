#!/bin/sh

dotnet restore ..
dotnet build --configuration Release --no-restore ..
dotnet test --no-restore --verbosity normal ..
