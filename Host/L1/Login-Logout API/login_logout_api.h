/**
  ******************************************************************************
  * File Name          : login_logout_api.h
  * Description        : L1 functions for the login and logout on the SEcube.
  ******************************************************************************
  *
  * Copyright � 2016-present Blu5 Group <https://www.blu5group.com>
  *
  * This library is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 3 of the License, or (at your option) any later version.
  *
  * This library is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this library; if not, see <https://www.gnu.org/licenses/>.
  *
  ******************************************************************************
  */

/*! \file  login_logout_api.h
 *  \brief This header file defines the L1 functions for the login and logout on the SEcube.
 *  \version SEcube Open Source SDK 1.5.1
 */

#include "../L1 Base/L1_base.h"

class LoginLogoutApi {
public:
	virtual ~LoginLogoutApi() {};
	/** @brief Login to the SEcube.
	 * @param [in] pin The pin to be used (the size of the PIN is always 32 byte).
	 * @param [in] access The privilege level (administrator or user).
	 * @param [in] force True to force logout if previous login still active on the SEcube, false otherwise.
	 * @detail The recommended value for the last parameter is always true. Since there is no return value, exceptions are triggered if
	 * any problem arises (i.e. wrong PIN); exceptions must be managed by the caller. */
	virtual void Login(const std::array<uint8_t, L1Parameters::Size::PIN>& pin, se3_access_type access, bool force) = 0;
	/** @brief Logout from the SEcube.
	 *  @detail Since there is no return value, exceptions are triggered if any problem arises (i.e. wrong PIN); exceptions must be managed by the caller. */
	virtual void Logout() = 0;
	/** @brief Same as standard logout, used internally by L1Login if force parameter is true.
	 *  @detail This function is not intended to be used explicitly. */
	virtual void Logout_forced() = 0;
	/** @brief Returns true if logged in, false otherwise.
	 *  @detail The returned value does not depend on the privilege associated to the login (i.e. administrator or user). */
	virtual bool LoggedIn() = 0;
	/** @brief Returns the privilege level obtained with the login operation. */
	virtual se3_access_type AccessType() = 0;
};
