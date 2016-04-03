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
#include <boost/program_options.hpp>
#include <boost/utility/string_ref.hpp>
#include <functional>
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

		struct SkipRowException {
			SkipRowException( ) = default;
			~SkipRowException( ) = default;
			SkipRowException( SkipRowException const & ) = default;
			SkipRowException( SkipRowException && ) = default;
			SkipRowException & operator=( SkipRowException const & ) = default;
			SkipRowException & operator=( SkipRowException && ) = default;
		};	// struct SkipRowException

		struct StopProcessingException {
			StopProcessingException( ) = default;
			~StopProcessingException( ) = default;
			StopProcessingException( StopProcessingException const & ) = default;
			StopProcessingException( StopProcessingException && ) = default;
			StopProcessingException & operator=( StopProcessingException const & ) = default;
			StopProcessingException & operator=( StopProcessingException && ) = default;
		};	// struct StopProcessingException
	
		namespace impl {
			class COMConnection;
			std::shared_ptr<COMConnection> intialize_COM( );

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
				Authentication( bool const PromptCredentials = false, bool const UseNtlm = true );
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


			CComPtr<IWbemLocator> obtain_wmi_locator( );

			CComPtr<IWbemServices> connect_to_server( CComPtr<IWbemLocator> & com_ptr, boost::wstring_ref host, Authentication & auth );

			template<typename T>
			void set_wmi_security( CComPtr<T> & com_ptr, Authentication &auth ) {
				HRESULT hres;
				if( FAILED( hres = CoSetProxyBlanket( com_ptr, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, auth.user_account( ), EOAC_NONE ) ) ) {
					std::stringstream ss;
					ss << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << ":" << _com_error( hres ).Description( );
					throw std::runtime_error( ss.str( ) );
				}
			}

			CComPtr<IEnumWbemClassObject> execute_wmi_query( CComPtr<IWbemServices> & com_ptr, boost::string_ref &query );

			CComPtr<IWbemClassObject> enumerator_next( CComPtr<IEnumWbemClassObject> & query_enumerator );
		}	// namespace impl

		

		template<typename T>
		std::vector<T> wmi_query( boost::wstring_ref host, boost::string_ref query, bool const prompt_credentials, std::function<T( IWbemWrapper )> callback, bool const use_ntlm = false ) {

			auto wmi_locator = impl::obtain_wmi_locator( );

			impl::Authentication auth( prompt_credentials, use_ntlm );

			// Connect to WMI through the IWbemLocator::ConnectServer method
			auto wmi_svc = connect_to_server( wmi_locator, host, auth );

			// Set security levels on a WMI connection ------------------
			impl::set_wmi_security( wmi_svc, auth );

			// Execute WMI query
			auto wmi_query_enum = impl::execute_wmi_query( wmi_svc, query );

			// Secure the enumerator proxy
			impl::set_wmi_security( wmi_query_enum, auth );


			std::vector<T> results;

			while( wmi_query_enum ) {				
				try {
					auto current_obj = impl::enumerator_next( wmi_query_enum );
					auto result = callback( IWbemWrapper( current_obj ) );
					results.push_back( std::move( result ) );
				} catch( SkipRowException const & ) {
					continue;
				} catch( StopProcessingException const & ) {
					break;
				}
			}
			return results;
		}

	}	// namespace wmi
}	// namespace daw
