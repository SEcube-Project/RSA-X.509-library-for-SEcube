/**
  ******************************************************************************
  * File Name          : utility_api.h
  * Description        : Prototypes of the utility API.
  ******************************************************************************
  *
  * Copyright 2016-present Blu5 Group <https://www.blu5group.com>
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

/*! \file  utility_api.h
 *  \brief Prototypes of the utility API.
 *  \version SEcube Open Source SDK 1.5.1
 *  \detail This header simply defines some functions that must be implemented by L1.
 */

#ifndef UTILITY_API_H_
#define UTILITY_API_H_

#include "../L1 Base/L1_base.h"

class UtilityApi {
public:
	virtual ~UtilityApi() {};
	/** @brief Select a specific SEcube out of multiple SEcube devices.
	 * @param [in] sn The serial number of the SEcube to be selected.
	 * @detail The selected SEcube will be the one used by the host PC to perform required actions (i.e. data encryption). Throws exception in case of errors. */
	virtual void Select_SEcube(std::array<uint8_t, L0Communication::Size::SERIAL>& sn) = 0;
	/** @brief Select a specific SEcube out of multiple SEcube devices.
	 * @param [in] indx The number of the SEcube to be selected.
	 * @details The selected SEcube will be the one used by the host PC to perform required actions (i.e. data encryption). The parameter is used to identify the SEcube in the
	 * list of SEcube devices that is returned by L0 GetDeviceList(). Throws exception in case of errors. */
	virtual void Select_SEcube(uint8_t indx) = 0;
	/** @brief Initialize the SEcube with the specified serial number (this is a wrapper of a similar L0 factory init function).
	 * @param [in] serialno The serial number to be set on the SEcube.
	 * @details Throws exception if the SEcube is already initialized (or in case of any error). Since it simply is a wrapper around the corresponding L0 function, this does not require to be logged in to the SEcube. */
	virtual void Factory_init(const std::array<uint8_t, L0Communication::Size::SERIAL>& serialno) = 0;
	/** @brief Get the serial number of the SEcube.
	 *  @param [out] sn The string where the serial number will be stored. */
	virtual void Get_SEcube_serialNumber(std::string& sn) = 0;
	/* @brief Set the PIN for administrator privilege level on the SEcube.
	 * @param [in] pin The PIN to be set.
	 * @detail Throws exception in case of errors. */
	virtual void Set_admin_pin(std::array<uint8_t, L1Parameters::Size::PIN>& pin) = 0;
	/* @brief Set the PIN for user privilege level on the SEcube.
	 * @param [in] pin The PIN to be set.
	 * @detail Throws exception in case of errors. */
	virtual void Set_user_pin(std::array<uint8_t, L1Parameters::Size::PIN>& pin) = 0;
};

#endif
