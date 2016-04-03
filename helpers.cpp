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

#include "helpers.h"

namespace daw {
	namespace wmi {
		namespace helpers {
			bool is_null( VARIANT const & v ) {
				return VT_NULL == v.vt;
			}

			boost::optional<int> find_logon_type( std::wstring const & value ) {
				auto result = daw::wmi::helpers::find_value<int>( value, L"Logon Type:" );
				return result;
			}

			boost::optional<std::wstring> find_security_id( std::wstring const & value ) {
				return daw::wmi::helpers::find_value<std::wstring>( value, L"Security ID:" );
			}

			boost::optional<std::wstring> find_account_name( std::wstring const & value ) {
				return daw::wmi::helpers::find_value<std::wstring>( value, L"Account Name:" );
			}

			boost::optional<std::wstring> find_account_domain( std::wstring const & value ) {
				return daw::wmi::helpers::find_value<std::wstring>( value, L"Account Domain:" );
			}

			std::wstring get_string( CComVariant const & v ) {
				daw::wmi::helpers::validate_variant_type( v, VT_BSTR );
				return std::wstring( v.bstrVal, SysStringLen( v.bstrVal ) );
			}

			std::wstring get_string( VARIANT const & v ) {
				daw::wmi::helpers::validate_variant_type( v, VT_BSTR );
				return std::wstring( v.bstrVal, SysStringLen( v.bstrVal ) );
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

			bool equal_eh( boost::optional<std::wstring> const & value1, boost::wstring_ref const value2 ) {
				auto const & v1 = *value1;
				auto result = static_cast<bool>(value1);
				result = result && v1.compare( value2.data( ) ) == 0;
				return result;
			}

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

			BOOL is_elevated( ) {				
				BOOL result = FALSE;
				HANDLE token = nullptr;
				if( OpenProcessToken( GetCurrentProcess( ), TOKEN_QUERY, &token ) ) {
					DWORD token_elevation_size = sizeof( TOKEN_ELEVATION );
					TOKEN_ELEVATION token_elevation;
					if( GetTokenInformation( token, TokenElevation, &token_elevation, sizeof( token_elevation ), &token_elevation_size ) ) {
						result = token_elevation.TokenIsElevated;
					}
				}
				if( token ) {
					CloseHandle( token );
				}
				return result;
			}

		}	// namespace helpers
	}	// namespace wmi
}	// namespace daw
