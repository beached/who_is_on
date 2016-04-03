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

#pragma once

#define _WIN32_DCOM
#ifndef UNICODE
#define UNICODE
#endif


#include <boost/algorithm/string.hpp>
#include <boost/optional.hpp>
#include <boost/utility/string_ref.hpp>
#include <cstdint>
#include <sstream>
#include <string>

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
#include <boost/utility/string_ref.hpp>
#include <atlbase.h>
#include "helpers.h"

namespace daw {
	namespace wmi {
		namespace helpers {
			bool is_null( VARIANT const & v );
			boost::optional<int> find_logon_type( std::wstring const & value );
			boost::optional<std::wstring> find_account_name( std::wstring const & value );
			boost::optional<std::wstring> find_account_domain( std::wstring const & value );
			boost::optional<std::wstring> find_security_id( std::wstring const & value );
			bool get_property( CComPtr<IWbemClassObject> const & pclsObj, boost::wstring_ref property_name, std::wstring & out_value );
			std::wstring get_string( CComVariant const & v );
			std::wstring get_string( VARIANT const & v );
			bool equal_eh( boost::optional<std::wstring> const & value1, boost::wstring_ref const value2 );
			std::wstring parse_stringtime( boost::wstring_ref time_string );

			template<typename T>
			void validate_variant_type( VARIANT const & v, T vt ) {
				if( v.vt != vt ) {
					std::stringstream ss;
					ss << "Mismatched type for get_value: requested->" << vt << " from type->" << v.vt;
					throw std::runtime_error( ss.str( ).c_str( ) );
				}
			}

			template<typename T>
			boost::optional<T> find_value( std::wstring const & value, boost::wstring_ref what ) {
				auto pos = value.find( what.to_string( ), 0 );
				if( std::wstring::npos == pos ) {
					// No login type field
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

			template<typename T, size_t Size>
			struct secure_wipe_array {
				T value[Size + 1];
				using value_type = T;
				using iterator = T *;
				using const_iterator = T const *;

				secure_wipe_array( ) {
					memset( value, 0, Size );
				}

				~secure_wipe_array( ) {
					SecureZeroMemory( value, sizeof( T ) * (Size + 1) );
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

			template<typename T>
			auto get_qp_value( T const & qp ) -> typename T::value_type {
				return qp.value;
			}


			//////////////////////////////////////////////////////////////////////////
			/// Summary:	convenience function to pull proper value from VARIANT
			/// Warning:	Make sure that your have the correct output type or bad 
			///				stuff happens.  BE CAREFUL!
			//////////////////////////////////////////////////////////////////////////
			template<typename T>
			T get_number( CComVariant const & v ) {
				switch( v.vt ) {
				case VT_UI1:
					return (T)v.bVal;
				case VT_UI2:
					return (T)v.uiVal;
				case VT_UI4:
					return (T)v.ulVal;
				case VT_INT:
					return (T)v.intVal;
				case VT_I2:
					return (T)v.iVal;
				case VT_I4:
					return (T)v.lVal;
				case VT_UINT:
					return (T)v.uintVal;
				case VT_R4:
					return (T)v.fltVal;
				case VT_R8:
					return (T)v.dblVal;
				case VT_BOOL:
					return (T)v.boolVal;
				case VT_DATE:
					return (T)v.date;
				default:
					throw std::runtime_error( "Unknown VARIANT type" );
				}
			}

			template<typename T>
			T get_number( VARIANT const & v ) {
				return get_number<T>( CComVariant( v ) );
			}

			template<typename T>
			bool equal_eh( boost::optional<T> const & value1, T const value2 ) {
				auto result = static_cast<bool>(value1);
				auto const & v1 = *value1;
				result = result && v1 == value2;
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

			BOOL is_elevated( );

		}	// namespace helpers
	}	// namespace wmi
}	// namespace daw
