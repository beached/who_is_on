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
#include "helpers.h"

std::wstring parse_stringtime( boost::wstring_ref time_string ) {
	std::wstringstream wss;

	auto year = time_string.substr( 0, 4 );
	auto month = time_string.substr( 4, 2 );
	auto day = time_string.substr( 6, 2 );
	auto hour = time_string.substr( 8, 2 );
	auto minute = time_string.substr( 10, 2 );
	auto second = time_string.substr( 12, 2 );

	wss << year << L"/" << month;
	wss << L"/" << day << L"/" << hour;
	wss << L":" << minute << L":" << second;

	return wss.str( );
}

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

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	auto hres = CoInitializeEx( nullptr, COINIT_MULTITHREADED );
	if( FAILED( hres ) ) {
		std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}
	BOOST_SCOPE_EXIT_ALL( &) {
		CoUninitialize( );
	};

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	if( FAILED( hres = CoInitializeSecurity( nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, nullptr, EOAC_NONE, nullptr ) ) ) {
		std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	CComPtr<IWbemLocator> pLoc = nullptr;

	if( FAILED( hres = CoCreateInstance( CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID *>(&pLoc) ) ) ) {
		std::cerr << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method


	CComPtr<IWbemServices> pSvc = nullptr;

	// Get the user name and password for the remote computer
	auto use_token = false;
	auto use_ntlm = true;

	helpers::secure_wipe_array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszName;
	helpers::secure_wipe_array<wchar_t, CREDUI_MAX_PASSWORD_LENGTH + 1> pszPwd;
	helpers::secure_wipe_array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszDomain;
	helpers::secure_wipe_array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszUserName;
	helpers::secure_wipe_array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszAuthority;

	if( prompt_credentials ) {
		CREDUI_INFO cui { };
		cui.cbSize = sizeof( CREDUI_INFO );
		cui.hwndParent = nullptr;
		// Ensure that MessageText and CaptionText identify
		// what credentials to use and which application requires them.
		cui.pszMessageText = TEXT( "Press cancel to use current user's token" );
		cui.pszCaptionText = TEXT( "Enter Account Information" );
		cui.hbmBanner = nullptr;
		BOOL fSave = FALSE;

		auto const dwErr = CredUIPromptForCredentials( &cui, TEXT( "" ), nullptr, 0, pszName.value, pszName.size( ), pszPwd.value, pszPwd.size( ), &fSave, CREDUI_FLAGS_GENERIC_CREDENTIALS | CREDUI_FLAGS_ALWAYS_SHOW_UI | CREDUI_FLAGS_DO_NOT_PERSIST );
		if( ERROR_CANCELLED == dwErr ) {
			use_token = true;
		} else if( dwErr ) {
			std::cerr << "Did not get credentials " << dwErr << std::endl;
			return EXIT_FAILURE;
		}
	} else {
		use_token = true;
	}

	// change the computerName strings below to the full computer name
	// of the remote computer
	if( !use_ntlm ) {
		StringCchPrintf( pszAuthority.value, pszAuthority.size( ), L"kERBEROS:%s", L"COMPUTERNAME" );
	}

	// Connect to the remote root\cimv2 namespace
	// and obtain pointer pSvc to make IWbemServices calls.
	//---------------------------------------------------------
	{
		// argv[1] is computer name
		auto const wmi_str =  L"\\\\" + remote_computer_name + L"\\root\\cimv2";
		hres = pLoc->ConnectServer(
			CComBSTR( wmi_str.c_str( ) ),
			CComBSTR( use_token ? nullptr : pszName.value ),    // User name
			CComBSTR( use_token ? nullptr : pszPwd.value ),     // User password
			nullptr,                              // Locale             
			0,                              // Security flags
			CComBSTR( use_ntlm ? nullptr : pszAuthority.value ),// Authority        
			nullptr,                              // Context object 
			&pSvc                              // IWbemServices proxy
		);
	}
	if( FAILED( hres ) ) {
		std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// step 5: --------------------------------------------------
	// Create COAUTHIDENTITY that can be used for setting security on proxy

	COAUTHIDENTITY *userAcct = nullptr;	// Never an owner
	COAUTHIDENTITY authIdent = { };

	if( !use_token ) {		
		authIdent.PasswordLength = static_cast<ULONG>(wcslen( pszPwd.value ));
		authIdent.Password = reinterpret_cast<USHORT*>(pszPwd.value);

		auto slash = reinterpret_cast<LPWSTR>(wcschr( pszName.value, L'\\' ));
		if( nullptr == slash ) {
			std::cerr << "Could not create Auth identity. No domain specified\n";
			return EXIT_FAILURE;
		}

		StringCchCopy( pszUserName.value, pszUserName.size( ), slash + 1 );
		authIdent.User = reinterpret_cast<USHORT*>(pszUserName.value);
		authIdent.UserLength = static_cast<ULONG>(wcslen( pszUserName.value ));

		StringCchCopyN( pszDomain.value, pszDomain.size( ), pszName.value, slash - pszName.value );
		authIdent.Domain = reinterpret_cast<USHORT*>(pszDomain.value);
		authIdent.DomainLength = static_cast<ULONG>(slash - pszName.value);
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		userAcct = &authIdent;

	}

	// Step 6: --------------------------------------------------
	// Set security levels on a WMI connection ------------------
	if( FAILED( hres = CoSetProxyBlanket( pSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, userAcct, EOAC_NONE ) ) ) {
		std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// Step 7: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	// For example, get the name of the operating system
	
	auto const wmi_query = CComBSTR( "Select * from Win32_NTLogEvent Where Logfile='Security' And (EventCode=4647 Or EventCode=4624)" );
	auto const wql = CComBSTR( "WQL" );

	CComPtr<IEnumWbemClassObject> pEnumerator = nullptr;
	if( FAILED( hres = pSvc->ExecQuery( wql, wmi_query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator ) ) ) {
		std::cerr << "Query for Security Eventlog." << " Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// Step 8: -------------------------------------------------
	// Secure the enumerator proxy
	if( FAILED( hres = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, userAcct, EOAC_NONE ) ) ) {
		std::cerr << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}


	// Step 9: -------------------------------------------------
	// Get the data from the query in step 7 -------------------

	ULONG uReturn = 0;

	std::vector<result_row> results;

	while( pEnumerator ) {
		CComPtr<IWbemClassObject> pclsObj;
		result_row current_result;

		auto hr = pEnumerator->Next( WBEM_INFINITE, 1, &pclsObj, &uReturn );
		if( FAILED( hr ) ) {
			std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
			break;
		} else if( 0 == uReturn ) {
			break;
		}

		current_result.event_code = 0;
		if( !helpers::get_property( pclsObj, L"EventCode", current_result.event_code ) ) {
			break;
		}

		std::wstring msg = L"";
		if( !helpers::get_property( pclsObj, L"Message", msg ) ) {
			break;
		}
			
		// If logon(event ID 4624) make sure we are interactive(logon type 2)
		if( 4624 == current_result.event_code && !helpers::compare( helpers::find_logon_type( msg ), 2 ) ) {
			continue;
		}
		
		// We don't want the SYSTEM account
		if(helpers::compare( helpers::find_security_id( msg ), L"S-1-5-18" ) ) {
			continue;
		}

		// User Name
		auto user_name = helpers::assign( helpers::find_account_domain( msg ), L"" ) + L"\\" + helpers::assign( helpers::find_account_name( msg ), L"" );


		// Computer Name
		current_result.computer_name = L"";
		if( !helpers::get_property( pclsObj, L"ComputerName", current_result.computer_name ) ) {
			break;
		}

		//Time Generated
		current_result.timestamp = L"";
		if( !helpers::get_property( pclsObj, L"TimeGenerated", current_result.timestamp ) ) {
			break;
		}
		current_result.sort_key = boost::lexical_cast<double>(current_result.timestamp.substr( 0, current_result.timestamp.size( ) - 4 ));
		current_result.timestamp = parse_stringtime( current_result.timestamp );

		// Category
		current_result.category = L"";
		if( !helpers::get_property( pclsObj, L"CategoryString", current_result.category ) ) {
			break;
		}

		results.push_back( std::move( current_result ) );
	}

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

	return EXIT_SUCCESS;   // Program successfully completed.

}