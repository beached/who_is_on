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

#include <atlbase.h>
#include <atlsafe.h>
#include <boost/program_options.hpp>
#include <boost/utility/string_ref.hpp>
#include <functional>
#include <iostream>
#include <strsafe.h>
#include <vector>
#include <Wbemidl.h>

#include "helpers.h"

namespace daw {
	namespace wmi {
		class IWbemWrapper {
			CComPtr<IWbemClassObject> m_obj;

		public:
			explicit IWbemWrapper( CComPtr<IWbemClassObject> obj );
			~IWbemWrapper( ) = default;
			IWbemWrapper( IWbemWrapper const & ) = delete;
			IWbemWrapper & operator=( IWbemWrapper const & ) = delete;
			IWbemWrapper( IWbemWrapper && ) = default;
			IWbemWrapper & operator=( IWbemWrapper && ) = default;

			template<typename T>
			bool operator( )( boost::wstring_ref property_name, T & out_value ) {
				return helpers::get_property( m_obj, property_name, out_value );
			}

			bool operator( )( boost::wstring_ref property_name, std::wstring & out_value );
		};	// class IWBemWrapper

		class COMConnection;
		std::shared_ptr<COMConnection> create_com_connection( );

		struct Authentication {
			using sec_array = daw::wmi::helpers::secure_wipe_array<wchar_t, CREDUI_MAX_USERNAME_LENGTH + 1>;
		private:
			sec_array m_name;			
			sec_array m_password;
			sec_array m_domain;
			sec_array m_user_name;
			sec_array m_authority;
			bool m_use_token;
			bool m_use_ntlm;
			COAUTHIDENTITY m_auth_ident;
			COAUTHIDENTITY* m_user_account;
		public:
			

			Authentication( bool PromptCredentials = false, bool UseNtlm = true );
			sec_array & name( );
			CComBSTR name_bstr( ) const;
			sec_array & password( );
			CComBSTR password_bstr( ) const;
			sec_array & domain( );
			sec_array & authority( );
			CComBSTR authoriy_bstr( ) const;
			bool & use_token( );
			bool & use_ntlm( );
			COAUTHIDENTITY* user_account( );
		};	// class Authentication

		struct SkipRowException {
			SkipRowException( ) = default;
			~SkipRowException( ) = default;
			SkipRowException( SkipRowException const & ) = default;
			SkipRowException( SkipRowException && ) = default;
			SkipRowException & operator=( SkipRowException const & ) = default;
			SkipRowException & operator=( SkipRowException && ) = default;
		};	// struct SkipRowException

		template<typename T>
		std::vector<T> wmi_query( boost::wstring_ref host, boost::string_ref query, bool prompt_credentials, std::function<T( IWbemWrapper )> callback, bool use_ntlm = true ) {
			// Obtain the initial locator to WMI 
			auto com_connection = create_com_connection( );

			CComPtr<IWbemLocator> pLoc;
			HRESULT hres;
				if( FAILED( hres = CoCreateInstance( CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<LPVOID *>(&pLoc) ) ) ) {
				std::stringstream ss;
				ss << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
				throw std::runtime_error( ss.str( ) );
			}

			Authentication auth( prompt_credentials, use_ntlm );

			// Connect to WMI through the IWbemLocator::ConnectServer method
			CComPtr<IWbemServices> pSvc;

			// Connect to the remote root\cimv2 namespace
			// and obtain pointer pSvc to make IWbemServices calls.
			//---------------------------------------------------------
			auto const wmi_str = L"\\\\" + host.to_string( ) + L"\\root\\cimv2";
			if( FAILED( hres = pLoc->ConnectServer( CComBSTR( wmi_str.c_str( ) ), auth.name_bstr( ), auth.password_bstr( ), nullptr, 0, auth.authoriy_bstr( ), nullptr, &pSvc ) ) ) {
				std::stringstream ss;
				ss << "Failed to create IWbemLocator object. Err code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
				throw std::runtime_error( ss.str( ) );
			}

			// Set security levels on a WMI connection ------------------
			if( FAILED( hres = CoSetProxyBlanket( pSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, auth.user_account( ), EOAC_NONE ) ) ) {
				std::stringstream ss;
				ss << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
				throw std::runtime_error( ss.str( ) );
			}

			// Use the IWbemServices pointer to make WMI query
			auto const wmi_query = CComBSTR( query.data( ) );
			auto const wql = CComBSTR( "WQL" );

			CComPtr<IEnumWbemClassObject> pEnumerator = nullptr;
			if( FAILED( hres = pSvc->ExecQuery( wql, wmi_query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator ) ) ) {
				std::stringstream ss;
				ss << "Query for Security Eventlog. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
				throw std::runtime_error( ss.str( ) );
			}

			// Secure the enumerator proxy
			if( FAILED( hres = CoSetProxyBlanket( pEnumerator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, auth.user_account( ), EOAC_NONE ) ) ) {
				std::stringstream ss;
				ss << "Could not set proxy blanket on enumerator. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).ErrorMessage( );
				throw std::runtime_error( ss.str( ) );
			}

			std::vector<T> results;

			while( pEnumerator ) {
				CComPtr<IWbemClassObject> pclsObj;
				
				ULONG uReturn = 0;

				auto hr = pEnumerator->Next( WBEM_INFINITE, 1, &pclsObj, &uReturn );
				if( FAILED( hr ) ) {
					std::cerr << "Error code = 0x" << std::hex << hr << std::endl;
					break;
				} else if( 0 == uReturn ) {
					break;
				}

				try {
					auto result = callback( IWbemWrapper( pclsObj ) );
					results.push_back( std::move( result ) );
				} catch( SkipRowException const & ) {
					// Do nothing
				}
			}
			return results;
		}

	}	// namespace wmi
}	// namespace daw
