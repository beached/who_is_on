// The MIT License (MIT)
// 
// Copyright (c) 2016 Darrell Wright
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define _WIN32_DCOM
#ifndef UNICODE
#define UNICODE
#endif
#include <exception>
#include <boost/program_options.hpp>
#include <iostream>
#include <sstream>
#include <comdef.h>
#include <Wbemidl.h>
#include <boost/scope_exit.hpp>


#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>
#include <atlbase.h>

#include <iostream>
#include <sstream>


#include "helpers.h"
#include "wmi_query.h"


struct result_row {
	double sort_key;
	std::wstring timestamp;
	std::wstring user_name;
	std::wstring computer_name;
	std::wstring category;
	int event_code;	
};	// struct result_row;

bool operator<( result_row const & lhs, result_row const & rhs ) {
	return lhs.sort_key < rhs.sort_key;
}

int __cdecl wmain( int argc, wchar_t *argv[] ) {
	bool show_header;
	std::wstring remote_computer_name;
	namespace po = boost::program_options;
	po::options_description desc( "Allowed options" );
	desc.add_options( )
		("help", "produce help message")
		("prompt", "prompt for network credentials")
		("show_header", "show field header in output")
		("computer_name", po::wvalue<std::wstring>( &remote_computer_name )->required( ), "Host name of computer to connect to.  Use . for local machine");

	po::positional_options_description positional_options;
	positional_options.add( "computer_name", 1 );

	po::variables_map vm;
	auto prompt_credentials = false;
	try {
		po::store( po::wcommand_line_parser( argc, argv ).options( desc ).positional( positional_options ).run( ), vm );
		po::notify( vm );


		if( vm.count( "help" ) ) {
			std::cout << desc << std::endl;
			return EXIT_SUCCESS;
		}
		prompt_credentials = vm.count( "prompt" ) != 0;
		show_header = vm.count( "show_header" ) != 0;
	} catch( po::required_option& e ) {
		std::cerr << "ERROR: " << e.what( ) << std::endl << std::endl;
		exit( EXIT_FAILURE );
	} catch( boost::program_options::error& e ) {
		std::cerr << "ERROR: " << e.what( ) << std::endl << std::endl;
		exit( EXIT_FAILURE );
	}

	std::string const wmi_query_str = "Select * from Win32_NTLogEvent Where Logfile='Security' And (EventCode=4647 Or EventCode=4624)";

	try {
		auto results = daw::wmi::wmi_query<result_row>( remote_computer_name, wmi_query_str, prompt_credentials, []( auto row_items ) {
			using namespace daw::wmi;
			using namespace daw::wmi::helpers;

			result_row current_result;
			current_result.event_code = 0;
			if( !row_items( L"EventCode", current_result.event_code ) ) {
				throw std::runtime_error( "Property not found: EventCode" );
			}

			std::wstring msg = L"";
			if( !row_items( L"Message", msg ) ) {
				throw std::runtime_error( "Property not found: Message" );
			}

			// If logon(event ID 4624) make sure we are interactive(logon type 2)
			if( 4624 == current_result.event_code && !equal_eh( find_logon_type( msg ), 2 ) ) {
				throw SkipRowException( );
			}

			// We don't want the SYSTEM account
			if( equal_eh( find_security_id( msg ), L"S-1-5-18" ) ) {
				throw SkipRowException( );
			}

			// User Name
			auto user_name = assign( find_account_domain( msg ), L"" ) + L"\\" + assign( find_account_name( msg ), L"" );


			// Computer Name
			current_result.computer_name = L"";
			if( !row_items( L"ComputerName", current_result.computer_name ) ) {
				throw std::runtime_error( "Property not found: ComputerName" );
			}

			//Time Generated
			current_result.timestamp = L"";
			if( !row_items( L"TimeGenerated", current_result.timestamp ) ) {
				throw std::runtime_error( "Property not found: TimeGenerated" );
			}
			current_result.sort_key = boost::lexical_cast<double>(current_result.timestamp.substr( 0, current_result.timestamp.size( ) - 4 ));
			current_result.timestamp = parse_stringtime( current_result.timestamp );

			// Category
			current_result.category = L"";
			if( !row_items( L"CategoryString", current_result.category ) ) {
				throw std::runtime_error( "Property not found: CategoryString" );
			}

			return current_result;
		} );

		std::sort( results.begin( ), results.end( ) );

		if( show_header ) {
			std::wcout << L"\"Timestamp\", \"User\", \"ComputerName\", \"Category\", \"EventCode\"\n";
		}
		for( auto const & result : results ) {
			std::wcout << L"\"" << result.timestamp << L"\"";
			std::wcout << L", \"" << result.user_name << L"\"";
			std::wcout << L", \"" << result.computer_name << L"\"";
			std::wcout << L", \"" << result.category << L"\"";
			std::wcout << L", " << result.event_code;
			std::wcout << "\n";
		}
	} catch( std::exception const & e ) {
		std::cerr << "Exception while running query:\n" << e.what( ) << std::endl;
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;   // Program successfully completed.

}