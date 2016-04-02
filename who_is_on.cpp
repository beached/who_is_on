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


template<typename T>
bool compare( boost::optional<T> const & value1, T const value2 ) {
	auto result = static_cast<bool>(value1);
	auto const & v1 = *value1;
	result = result && v1 == value2;
	return result;
}

bool compare( boost::optional<std::wstring> const & value1, boost::wstring_ref const value2 ) {
	auto const & v1 = *value1;
	auto result = static_cast<bool>( value1 );
	result = result && v1.compare( value2.data( ) ) == 0;
	return result;
}

template<typename T, typename U>
T assign( boost::optional<T> v, U def_value ) {
	if( v ) {
		return *v;
	} else {
		return def_value;
	}
}

template<typename T>
bool get_property( CComPtr<IWbemClassObject> const & pclsObj, boost::wstring_ref property_name, T & out_value ) {
	CComVariant vtProp;
	auto hr = pclsObj->Get( property_name.data( ), 0, &vtProp, nullptr, nullptr );
	if( FAILED( hr ) ) {
		std::wcerr << L"Error code = 0x" << std::hex << hr << std::endl;
		return false;
	}
	out_value = helpers::get_number<T>( vtProp );
	return true;
}

bool get_property( CComPtr<IWbemClassObject> const & pclsObj, boost::wstring_ref property_name, std::wstring & out_value ) {
	CComVariant vtProp;
	auto hr = pclsObj->Get( property_name.data( ), 0, &vtProp, nullptr, nullptr );
	if( FAILED( hr ) ) {
		std::wcerr << L"Error code = 0x" << std::hex << hr << std::endl;
		return false;
	}
	out_value = helpers::get_string( vtProp );
	return true;
}


int __cdecl wmain( int argc, wchar_t *argv[] ) {
	auto prompt_credentials = false;
	if( argc < 2 ) {
		std::cerr << "Must specify computer name on command line e.g " << argv[0] << " COMPUTERNAME\n";
	} else if( argc >= 3 ) {
		prompt_credentials = 0 == wcscmp( L"prompt", argv[2] );
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

	hres = CoInitializeSecurity(
		nullptr,
		-1,                          // COM authentication
		nullptr,                        // Authentication services
		nullptr,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
		nullptr,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		nullptr                         // Reserved
	);


	if( FAILED( hres ) ) {
		std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	CComPtr<IWbemLocator> pLoc = nullptr;

	hres = CoCreateInstance( CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID *>(&pLoc) );

	if( FAILED( hres ) ) {
		std::cerr << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;                 // Program has failed.
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

		auto dwErr = CredUIPromptForCredentials(
			&cui,                             // CREDUI_INFO structure
			TEXT( "" ),                         // Target for credentials
			nullptr,                             // Reserved
			0,                                // Reason
			pszName.value,                          // User name
			pszName.size( ),     // Max number for user name
			pszPwd.value,                           // Password
			pszPwd.size( ),	// Max number for password
			&fSave,                           // State of save check box
			CREDUI_FLAGS_GENERIC_CREDENTIALS |// flags
			CREDUI_FLAGS_ALWAYS_SHOW_UI |
			CREDUI_FLAGS_DO_NOT_PERSIST );

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
		std::wstringstream wss;
		wss << L"\\\\" << argv[1] << L"\\root\\cimv2";
		hres = pLoc->ConnectServer(
			CComBSTR( wss.str( ).c_str( ) ),
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
	hres = CoSetProxyBlanket(
		pSvc,                           // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		userAcct,                       // client identity
		EOAC_NONE                       // proxy capabilities 
	);

	if( FAILED( hres ) ) {
		std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// Step 7: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	// For example, get the name of the operating system
	
	auto const wmi_query = CComBSTR( "Select * from Win32_NTLogEvent Where Logfile='Security' And (EventCode=4647 Or EventCode=4624)" );
	auto const wql = CComBSTR( "WQL" );

	CComPtr<IEnumWbemClassObject> pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		wql,
		wmi_query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator );

	if( FAILED( hres ) ) {
		std::cerr << "Query for Security Eventlog." << " Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}

	// Step 8: -------------------------------------------------
	// Secure the enumerator proxy
	hres = CoSetProxyBlanket(
		pEnumerator,                    // Indicates the proxy to set
		RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
		COLE_DEFAULT_PRINCIPAL,         // Server principal name 
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
		userAcct,                       // client identity
		EOAC_NONE                       // proxy capabilities 
	);

	if( FAILED( hres ) ) {
		std::cerr << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;
	}



	// Step 9: -------------------------------------------------
	// Get the data from the query in step 7 -------------------

	CComPtr<IWbemClassObject> pclsObj = nullptr;
	ULONG uReturn = 0;

	auto show_header = true;
	if( show_header ) {
		std::wcout << "\"ComputerName\", \"SourceName\", \"Type\", \"CategoryString\", \"EventCode\", \"User\"\n";
	}

	while( pEnumerator ) {
		auto hr = pEnumerator->Next( WBEM_INFINITE, 1, &pclsObj, &uReturn );
		if( FAILED( hr ) ) {
			std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
			break;
		} else if( 0 == uReturn ) {
			break;
		} else {
			CComVariant vtProp;
			BOOST_SCOPE_EXIT_ALL( &) {
				vtProp.Clear( );
				pclsObj.Release( );
			};

			auto event_code = 0;
			if( !get_property( pclsObj, L"EventCode", event_code ) ) {
				break;
			}

			std::wstring msg = L"";
			if( !get_property( pclsObj, L"Message", msg ) ) {
				break;
			}
			
			// If logon(event ID 4624) make sure we are interactive(logon type 2)
			if( 4624 == event_code ) {
				if( !compare( helpers::find_logon_type( msg ), 2 ) ) {
					continue;
				}				
			}
			
			// We don't want the SYSTEM account
			if( compare( helpers::find_security_id( msg ), L"S-1-5-18" ) ) {
				continue;
			}

			// Computer Name
			std::wstring computer_name = L"";
			if( !get_property( pclsObj, L"ComputerName", computer_name ) ) {
				break;
			}
			std::wcout << L"\"" << computer_name << L"\"";

			// User Name
			std::wcout << L", \"" << assign( helpers::find_account_domain( msg ), L"" );
			std::wcout << L"\\" << assign( helpers::find_account_name( msg ), L"" ) << L"\"";

			//Time Generated
			std::wstring stime_generated = L"";
			if( !get_property( pclsObj, L"TimeGenerated", stime_generated ) ) {
				break;
			}
			SYSTEMTIME time_generated = { };

			auto year = stime_generated.substr( 0, 4 );
			auto month = stime_generated.substr( 4, 2 );
			auto day = stime_generated.substr( 6, 2 );
			auto hour = stime_generated.substr( 8, 2 );
			auto minute = stime_generated.substr( 10, 2 );
			auto second = stime_generated.substr( 12, 2 );

			std::wcout << L", \"" << year << L"/" << month;
			std::wcout << L"/" << day << L"/" << hour;
			std::wcout << L":" << minute << L":" << second << L"\"";

			// Category
			std::wstring category_string = L"";
			if( !get_property( pclsObj, L"CategoryString", category_string ) ) {
				break;
			}
			std::wcout << L", \"" << category_string << L"\"";

			std::wcout << L", " << event_code;

			std::wcout << "\n";
		}
	}


	return EXIT_SUCCESS;   // Program successfully completed.

}