cmake_minimum_required(VERSION 3.10)
project(bbr_loader C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)

# Buscar paquetes de SDL2 en Linux
find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)

# Incluir las rutas de origen y librerías internas
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/source
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
    ${SDL2_INCLUDE_DIRS}
)

# Recopilar todos los archivos de código del proyecto
file(GLOB_RECURSE SOURCES "source/*.c" "source/*.cpp" "lib/*.c" "lib/*.cpp")

# Crear ejecutable
add_executable(bbr ${SOURCES})

# Vincular librerías Linux ARM
target_link_libraries(bbr PRIVATE
    ${SDL2_LIBRARIES}
    GLESv2
    EGL
    dl
    m
    pthread
)
