if "%APPVEYOR_REPO_TAG%" == "true" (
    conan create %APPVEYOR_BUILD_FOLDER% "%APPVEYOR_PROJECT_NAME%/%APPVEYOR_REPO_TAG_NAME:v=%@barco/healthcare" -s build_type=%configuration% -s compiler="Visual Studio" -s compiler.version=%MSVC_VERSION%
    conan upload --remote barco --all %APPVEYOR_PROJECT_NAME%/%APPVEYOR_REPO_TAG_NAME:v=%@barco/healthcare
) else (
    if "%APPVEYOR_REPO_BRANCH%" == "barco_1.0.22" (
        conan create %APPVEYOR_BUILD_FOLDER% %APPVEYOR_PROJECT_NAME%/1.0.22.0@barco/healthcare -s build_type=%configuration% -s compiler="Visual Studio" -s compiler.version=%MSVC_VERSION%
        conan upload --remote barco --all --force %APPVEYOR_PROJECT_NAME%/1.0.22.0@barco/healthcare
    )
)
