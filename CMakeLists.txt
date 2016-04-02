cmake_minimum_required( VERSION 2.8.4 )
project( who_is_on )

set( Boost_USE_STATIC_LIBS OFF )
set( Boost_USE_MULTITHREADED ON )
set( Boost_USE_STATIC_RUNTIME OFF )
find_package( Boost 1.55.0 REQUIRED COMPONENTS system filesystem regex unit_test_framework program_options iostreams )
set( Boost_Libs ${BOOST_Libraries} -lboost_system -lboost_regex -lboost_filesystem -lboost_program_options -lboost_iostreams )

set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_WIN32_WINNT=0x0601 /MP" )
set( Boost_Libs )

# force the correct version for the redist manifest
ADD_DEFINITIONS(-D_BIND_TO_CURRENT_MFC_VERSION=1 -D_BIND_TO_CURRENT_CRT_VERSION=1)

set( SOURCE_FILES
	helpers.cpp
	helpers.h
	who_is_on.cpp	
)

include_directories( SYSTEM ${Boost_INCLUDE_DIRS} )
link_directories( ${Boost_LIBRARY_DIRS} )

add_executable( who_is_on ${SOURCE_FILES} )
target_link_libraries( who_is_on ${CMAKE_DL_LIBS} ${Boost_Libs} ${CMAKE_THREAD_LIBS_INIT} ${COMPILER_SPECIFIC_LIBS} )
