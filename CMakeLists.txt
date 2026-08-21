cmake_minimum_required(VERSION 3.10)
project(bbr_loader C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

# Buscar paquetes de SDL2 y OpenGL ES en Linux
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)

# Incluir carpetas del proyecto
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/source
    ${SDL2_INCLUDE_DIRS}
)

# Recopilar archivos fuente
file(GLOB_RECURSE SOURCES "source/*.c" "source/*.cpp")

# Crear el ejecutable binario
add_executable(bbr ${SOURCES})

# Vincular librerías del sistema Linux ARM
target_link_libraries(bbr PRIVATE
    ${SDL2_LIBRARIES}
    GLESv2
    EGL
    dl
    m
    pthread
)
