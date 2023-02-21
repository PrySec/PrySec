#!/bin/sh

dotnet restore ..
dotnet build --configuration Debug --no-restore ..
dotnet test --no-restore --verbosity normal ..
