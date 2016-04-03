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

#include <algorithm>
#include <boost/program_options.hpp>
#include <exception>
#include <iostream>
#include "wmi_query.h"


struct result_row {
	double sort_key;
	std::wstring timestamp = L"";
	std::wstring user_name = L"";
	std::wstring computer_name = L"";
	std::wstring category = L"";
	int event_code = 0;

	// operator< for sorting
	bool operator<( result_row const & rhs ) const {
		return sort_key < rhs.sort_key;
	}
};	// struct result_row;

template<typename E = std::runtime_error>
void throw_on_false( bool test, boost::string_ref err_msg ) {
	if( !test ) {
		throw E( err_msg.to_string( ) );
	}
}


int __cdecl wmain( int argc, wchar_t *argv[] ) {

	auto parsed_args = [&argc, &argv]( ) {	// Parse command line
		struct {
			bool show_header = false;
			bool prompt_credentials = false;
			std::wstring remote_computer_name = L"";
		} result;

		namespace po = boost::program_options;
		po::options_description desc( "Allowed options" );
		desc.add_options( )
			("help", "produce help message")
			("prompt", "prompt for network credentials")
			("show_header", "show field header in output")
			("computer_name", po::wvalue<std::wstring>( ), "Host name of remote computer to connect to.");

		po::variables_map vm;

		try {
			po::store( po::parse_command_line( argc, argv, desc ), vm );
			po::notify( vm );

			if( vm.count( "help" ) ) {
				std::cout << desc << std::endl;
				exit( EXIT_SUCCESS );
			}

			result.prompt_credentials = vm.count( "prompt" ) != 0;
			result.show_header = vm.count( "show_header" ) != 0;
			if( 0 != vm.count( "computer_name" ) ) {
				result.remote_computer_name = vm["computer_name"].as<std::wstring>( );
				if( result.prompt_credentials ) {
					std::wcerr << "Warning: When connecting locally cannot prompt for credentials\n";
					result.prompt_credentials = false;
				}
			}
		} catch( po::required_option& e ) {
			std::cerr << "ERROR: " << e.what( ) << std::endl << std::endl;
			exit( EXIT_FAILURE );
		} catch( boost::program_options::error& e ) {
			std::cerr << "ERROR: " << e.what( ) << std::endl << std::endl;
			exit( EXIT_FAILURE );
		}
		return result;
	}();

	try {
		std::string const wmi_query_str = "Select * from Win32_NTLogEvent Where Logfile='Security' And (EventCode=4647 Or EventCode=4624)";
		auto results = daw::wmi::wmi_query<result_row>( parsed_args.remote_computer_name, wmi_query_str, parsed_args.prompt_credentials, []( auto row_items ) {
			using namespace daw::wmi;
			using namespace daw::wmi::helpers;

			result_row current_result;
			throw_on_false( row_items( L"EventCode", current_result.event_code ), "Property not found: EventCode" );			

			std::wstring msg = L"";
			throw_on_false( row_items( L"Message", msg ), "Property not found: Message" );
			

			// If logon(event ID 4624) make sure we are interactive(logon type 2)
			if( 4624 == current_result.event_code && !equal_eh( find_logon_type( msg ), 2 ) ) {
				throw SkipRowException( );
			}

			// We don't want the SYSTEM account
			if( equal_eh( find_security_id( msg ), L"S-1-5-18" ) ) {
				throw SkipRowException( );
			}

			// User Name
			current_result.user_name = assign( find_account_domain( msg ), L"" ) + L"\\" + assign( find_account_name( msg ), L"" );

			// Computer Name
			throw_on_false( !row_items( L"ComputerName", current_result.computer_name ), "Property not found: ComputerName" );

			//Time Generated
			throw_on_false( !row_items( L"TimeGenerated", current_result.timestamp ), "Property not found: TimeGenerated" );
			current_result.sort_key = boost::lexical_cast<double>(current_result.timestamp.substr( 0, current_result.timestamp.size( ) - 4 ));
			current_result.timestamp = parse_stringtime( current_result.timestamp );

			// Category
			throw_on_false( !row_items( L"CategoryString", current_result.category ), "Property not found: CategoryString" );

			return current_result;
		} );

		std::sort( std::begin( results ), std::end( results ) );

		if( parsed_args.show_header ) {
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
		exit( EXIT_FAILURE );
	}
	return EXIT_SUCCESS;   // Program successfully completed.

}