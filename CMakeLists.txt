#cmake -G "MinGW Makefiles" - for Window
cmake_minimum_required (VERSION 3.22)

project ("main")

set(CMAKE_CXX_STANDARD 20)

if(WIN32)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")
endif()

file (GLOB CPPM "*.cpp" HM "*.h")

find_package(OpenSSL REQUIRED)

add_executable (${PROJECT_NAME} ${CPPM} ${HM})

if(WIN32)
  target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto ws2_32)
  else() 
  target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()
