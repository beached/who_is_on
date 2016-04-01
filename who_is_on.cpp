/*
The MIT License (MIT)

Copyright (c) 2016 Darrell Wright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#define _WIN32_DCOM
#ifndef UNICODE
#define UNICODE
#endif
#include <exception>
#include <iostream>
#include <sstream>
#include <comdef.h>
#include <Wbemidl.h>
#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
#include <boost/scope_exit.hpp>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>
#include <boost/utility/string_ref.hpp>
#include <atlbase.h>

template<typename T>
struct GetValue {
	void operator( )( VARIANT const & v ) {
		std::stringstream ss;
		ss << "Unknown type for get_value: " << v.vt;
		throw std::runtime_error( ss.str( ).c_str( ) );
	}
};

template<typename T>
void validate_variant_type( VARIANT const & v, T vt ) {
	if( v.vt != vt ) {
		std::stringstream ss;
		ss << "Missmatched type for get_value: requested->" << vt << " from type->" << v.vt;
		throw std::runtime_error( ss.str( ).c_str( ) );
	}
}

bool is_null( VARIANT const & v ) {
	return VT_NULL == v.vt;
}

template<>
struct GetValue<std::wstring> {
	std::wstring operator( )( VARIANT const & v ) const {
		if( is_null( v ) ) {
			return L"";
		}
		validate_variant_type( v, VT_BSTR );
		return boost::replace_all_copy( std::wstring( v.bstrVal, SysStringLen( v.bstrVal ) ), L"\"", L"\\\"" );
	}
};

template<>
struct GetValue<unsigned int> {
	unsigned int operator( )( VARIANT const & v ) const {
		validate_variant_type( v, VT_UINT );
		return v.uintVal;
	}
};

template<>
struct GetValue<uint16_t> {
	uint16_t operator( )( VARIANT const & v ) {
		validate_variant_type( v, VT_UI2 );
		return v.uintVal;
	}
};

template<>
struct GetValue<int32_t> {
	int32_t operator( )( VARIANT const & v ) {
		validate_variant_type( v, VT_I4 );
		return v.uintVal;
	}
};

template<typename T>
boost::optional<T> find_value( std::wstring const & value, boost::wstring_ref what ) {
	auto pos = value.find( what.to_string( ), 0 );
	if( std::wstring::npos == pos ) {
		// No logon type field
		return boost::optional<T>( );
	}
	pos += what.size( );

	pos = value.find_first_not_of( L" \t\r\n", pos );
	if( std::wstring::npos == pos ) {
		// No non-blanks
		return boost::optional<T>( );
	}
	auto pos2 = value.find_first_of( L" \t\r\n", pos );
	if( std::wstring::npos == pos2 ) {
		// No non-blanks
		return boost::optional<T>( );
	}
	std::wstringstream wss;
	wss << value.substr( pos, pos2 - pos );
	T result;
	wss >> result;
	return boost::optional<T>( result );
}

boost::optional<int> find_logon_type( std::wstring const & value ) {
	return find_value<int>( value, L"Logon Type:" );
}

boost::optional<std::wstring> find_account_name( std::wstring const & value ) {
	return find_value<std::wstring>( value, L"Account Name:" );
}

boost::optional<std::wstring> find_account_domain( std::wstring const & value ) {
	return find_value<std::wstring>( value, L"Account Domain:" );
}

template<typename Char_t, size_t Size>
struct sec_cstr {
	Char_t value[Size + 1];
	using value_type = Char_t;
	using iterator = Char_t *;
	using const_iterator = Char_t const *;

	sec_cstr( ) {
		memset( value, 0, Size );
	}

	~sec_cstr( ) {
		SecureZeroMemory( value, sizeof( Char_t ) * (Size + 1) );
	}

	iterator begin( ) {
		return value;
	}

	constexpr const_iterator begin( ) const {
		return value;
	}

	iterator end( ) {
		return value + Size;
	}

	constexpr const_iterator end( ) const {
		return value + Size;
	}

	constexpr size_t size( ) const {
		return Size;
	}
};

struct QueryParam {
	std::wstring name;
	virtual ~QueryParam( ) = 0;
};

struct StringQueryParam: public QueryParam {
	std::wstring value;
	using value_type = std::wstring;
};

struct Int32QueryParam: public QueryParam {
	int32_t value;
	using value_type = int32_t;
};

template<typename T>
auto get_qp_value( T const & qp ) -> typename T::value_type {
	return qp.value;
}

int __cdecl wmain( int argc, wchar_t *argv[] ) {
	auto prompt_credentials = false;
	if( argc < 2 ) {
		std::cerr << "Must specify computername on commandline e.g " << argv[0] << " COMPUTERNAME\n";
	} else if( argc >= 3 ) {
		prompt_credentials = 0 == wcscmp( L"prompt", argv[2] );
	}
	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	auto hres = CoInitializeEx( 0, COINIT_MULTITHREADED );
	if( FAILED( hres ) ) {
		std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
		return EXIT_FAILURE;                  // Program has failed.
	}

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
		CoUninitialize( );
		return EXIT_FAILURE;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	CComPtr<IWbemLocator> pLoc = nullptr;

	hres = CoCreateInstance( CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc );

	if( FAILED( hres ) ) {
		std::cerr << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << std::endl;
		CoUninitialize( );
		return EXIT_FAILURE;                 // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method


	CComPtr<IWbemServices> pSvc = nullptr;

	// Get the user name and password for the remote computer
	bool useToken = false;
	bool useNTLM = true;
	sec_cstr<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszName;
	sec_cstr<wchar_t, CREDUI_MAX_PASSWORD_LENGTH + 1> pszPwd;
	sec_cstr<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszDomain;
	sec_cstr<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszUserName;
	sec_cstr<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1> pszAuthority;

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
			useToken = true;
		} else if( dwErr ) {
			std::cerr << "Did not get credentials " << dwErr << std::endl;
			pLoc.Release( );
			CoUninitialize( );
			return EXIT_FAILURE;
		}
	} else {
		useToken = true;
	}

	// change the computerName strings below to the full computer name
	// of the remote computer
	if( !useNTLM ) {
		StringCchPrintf( pszAuthority.value, pszAuthority.size( ), L"kERBEROS:%s", L"COMPUTERNAME" );
	}

	// Connect to the remote root\cimv2 namespace
	// and obtain pointer pSvc to make IWbemServices calls.
	//---------------------------------------------------------
	{
		// argv[1] is computername
		std::wstringstream wss;
		wss << L"\\\\" << argv[1] << L"\\root\\cimv2";
		hres = pLoc->ConnectServer(
			_bstr_t( wss.str( ).c_str( ) ),
			_bstr_t( useToken ? nullptr : pszName.value ),    // User name
			_bstr_t( useToken ? nullptr : pszPwd.value ),     // User password
			nullptr,                              // Locale             
			0,                              // Security flags
			_bstr_t( useNTLM ? nullptr : pszAuthority.value ),// Authority        
			nullptr,                              // Context object 
			&pSvc                              // IWbemServices proxy
		);
	}
	if( FAILED( hres ) ) {
		std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
		pLoc.Release( );
		CoUninitialize( );
		return EXIT_FAILURE;                // Program has failed.
	}

	// step 5: --------------------------------------------------
	// Create COAUTHIDENTITY that can be used for setting security on proxy

	COAUTHIDENTITY *userAcct = nullptr;
	COAUTHIDENTITY authIdent;


	if( !useToken ) {
		memset( &authIdent, 0, sizeof( COAUTHIDENTITY ) );
		authIdent.PasswordLength = wcslen( pszPwd.value );
		authIdent.Password = (USHORT*)pszPwd.value;

		LPWSTR slash = wcschr( pszName.value, L'\\' );
		if( nullptr == slash ) {
			std::cerr << "Could not create Auth identity. No domain specified\n";
			pSvc.Release( );
			pLoc.Release( );
			CoUninitialize( );
			return EXIT_FAILURE;               // Program has failed.
		}

		StringCchCopy( pszUserName.value, pszUserName.size( ), slash + 1 );
		authIdent.User = (USHORT*)pszUserName.value;
		authIdent.UserLength = wcslen( pszUserName.value );

		StringCchCopyN( pszDomain.value, pszDomain.size( ), pszName.value, slash - pszName.value );
		authIdent.Domain = (USHORT*)pszDomain.value;
		authIdent.DomainLength = slash - pszName.value;
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
		pSvc.Release( );
		pLoc.Release( );
		CoUninitialize( );
		return EXIT_FAILURE;               // Program has failed.
	}

	// Step 7: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----
	std::string const wmi_query = "Select * from Win32_NTLogEvent Where Logfile='Security' And (EventCode=4647 Or EventCode=4624)";
	// For example, get the name of the operating system

	CComPtr<IEnumWbemClassObject> pEnumerator = nullptr;
	hres = pSvc->ExecQuery(
		bstr_t( "WQL" ),
		bstr_t( wmi_query.c_str( ) ),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&pEnumerator );

	if( FAILED( hres ) ) {
		std::cerr << "Query for Security Eventlog." << " Error code = 0x" << std::hex << hres << std::endl;
		pSvc.Release( );
		pLoc.Release( );
		CoUninitialize( );
		return EXIT_FAILURE;               // Program has failed.
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
		pEnumerator.Release( );
		pSvc.Release( );
		pLoc.Release( );
		CoUninitialize( );
		return EXIT_FAILURE;               // Program has failed.
	}



	// Step 9: -------------------------------------------------
	// Get the data from the query in step 7 -------------------

	CComPtr<IWbemClassObject> pclsObj = nullptr;
	ULONG uReturn = 0;
	GetValue<std::wstring> show_str;
	GetValue<int32_t> show_int32;
	bool show_header = true;
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
			VARIANT vtProp;
			BOOST_SCOPE_EXIT_ALL( &) {
				VariantClear( &vtProp );
				pclsObj.Release( );
				pclsObj = nullptr;
			};
			hr = pclsObj->Get( L"EventCode", 0, &vtProp, 0, 0 );
			if( FAILED( hr ) ) {
				std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
				break;
			}
			auto event_code = show_int32( vtProp );
			boost::optional<std::wstring> account_name;
			boost::optional<std::wstring> account_domain;

			{
				hr = pclsObj->Get( L"Message", 0, &vtProp, nullptr, nullptr );
				if( FAILED( hr ) ) {
					std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
					break;
				}
				auto const msg = show_str( vtProp );
				if( 4624 == event_code ) {	// logon event id
											// Only want logon type 2, interactive					
					auto logon_type = find_logon_type( msg );
					if( !logon_type || *logon_type != 2 ) {
						continue;
					}
				}
				account_name = find_account_name( msg );
				if( !account_name ) {
					// Could not find a security id
					account_name = L"";
				}
				account_domain = find_account_domain( msg );
				if( !account_domain ) {
					// Could not find a security id
					account_domain = L"";
				}


			}
			hr = pclsObj->Get( L"ComputerName", 0, &vtProp, 0, 0 );

			if( FAILED( hr ) ) {
				std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
				break;
			}
			////////////////////////////////////////////////////////////////////////
			std::wcout << L"\"" << show_str( vtProp ) << L"\"";

			hr = pclsObj->Get( L"CategoryString", 0, &vtProp, 0, 0 );
			if( FAILED( hr ) ) {
				std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
				break;
			}
			std::wcout << L", \"" << show_str( vtProp ) << L"\"";

			std::wcout << L", " << event_code;

			std::wcout << L", \"" << *account_domain << L"\\" << *account_name << L"\"";

			std::wcout << "\n";
		}
	}

	// Cleanup
	// ========

	pSvc.Release( );
	pLoc.Release( );
	pEnumerator.Release( );
	if( pclsObj ) {
		pclsObj.Release( );
	}

	CoUninitialize( );

	return EXIT_SUCCESS;   // Program successfully completed.

}