##
# Copyright (C) 2015 Tirasa (info@tirasa.net)
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use @file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

module Adsddl
  ##
  # Standard ACE rights.
  ##
  class ObjectRight
    attr_reader :value
    attr_accessor :name

    ##
    # Private constructor.
    #
    # @param value int value.
    ##
    def initialize(value)
      @value = value
    end

    ##
    # GENERIC_READ - When read access to an object is requested, @bit is translated to a combination of bits.
    # These are most often set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
    # specify a different configuration.) The bits that are set are implementation dependent. During this
    # translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
    # checked against the ACE structures in the security descriptor that attached to the object.
    #
    # When the GR bit is set in an ACE that is to be attached to an object, it is translated into a combination of
    # bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
    # specify a different configuration.) The bits that are set are implementation dependent. During this
    # translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
    # granted by @ACE.
    ##
    GR = new(0x80000000)
    ##
    # GENERIC_WRITE - When write access to an object is requested, @bit is translated to a combination of bits
    # which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
    # specify a different configuration.) The bits that are set are implementation dependent. During this
    # translation, the GW bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
    # checked against the ACE structures in the security descriptor that attached to the object.
    #
    # When the GW bit is set in an ACE that is to be
    # attached to an object, it is translated into a combination of bits, which are usually set in the lower 16
    # bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits
    # that are set are implementation dependent. During @translation, the GW bit is cleared. The resulting
    # ACCESS_MASK bits are the actual permissions that are granted by @ACE.
    ##
    GW = new(0x40000000)
    ##
    # GENERIC_EXECUTE - When execute access to an object is requested, @bit is translated to a combination of
    # bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
    # specify a different configuration.) The bits that are set are implementation dependent. During this
    # translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
    # checked against the ACE structures in the security descriptor that attached to the object.
    #
    # When the GX bit is set in an ACE that is to be attached to an object, it is translated into a combination of
    # bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
    # specify a different configuration.) The bits that are set are implementation dependent. During this
    # translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
    # granted by @ACE.
    ##
    GX = new(0x20000000)
    ##
    # GENERIC_ALL - When all access permissions to an object are requested, @bit is translated to a combination
    # of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications
    # MAY specify a different configuration.) Objects are free to include bits from the upper 16 bits in that
    # translation as required by the objects semantics. The bits that are set are implementation dependent. During
    # @translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
    # checked against the ACE structures in the security descriptor that attached to the object.
    #
    # When the GA bit is set in an ACE that is to be attached to an object, it is translated into a combination of
    # bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
    # specify a different configuration.) Objects are free to include bits from the upper 16 bits in that
    # translation, if required by the objects semantics. The bits that are set are implementation dependent.
    # During @translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions
    # that are granted by @ACE.
    ##
    GA = new(0x10000000)
    ##
    # MAXIMUM_ALLOWED - When requested, @bit grants the requestor the maximum permissions allowed to the
    # object through the Access Check Algorithm. This bit can only be requested it cannot be set in an ACE.
    #
    # Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set
    # and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
    ##
    MA = new(0x02000000)
    ##
    # ACCESS_SYSTEM_SECURITY - When requested, @bit grants the requestor the maximum permissions allowed to the
    # object through the Access Check Algorithm. This bit can only be requested it cannot be set in an ACE.
    #
    # Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set
    # and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
    ##
    AS = new(0x01000000)
    ##
    # SYNCHRONIZE - Specifies access to the object sufficient to synchronize or wait on the object.
    ##
    SY = new(0x00100000)
    ##
    # WRITE_OWNER - Specifies access to change the owner of the object as listed in the security descriptor.
    ##
    WO = new(0x00080000)
    ##
    # WRITE_DACL - Specifies access to change the discretionary access control list of the security descriptor of
    # an object.
    ##
    WD = new(0x00040000)
    ##
    # READ_CONTROL - Specifies access to read the security descriptor of an object.
    ##
    RC = new(0x00020000)
    ##
    # DELETE - Specifies access to delete an object.
    ##
    SD = new(0x00010000)
    ##
    # ADS_RIGHT_DS_CONTROL_ACCESS - The ObjectType GUID identifies an extended access right.
    ##
    CR = new(0x00000100)

    # FA = new(0x001F01FF)
    # FX = new(0x001200A0)
    # FW = new(0x00100116)
    # FR = new(0x00120089)
    # KA = new(0x00000019)
    # KR = new(0x0000003F)
    # KX = new(0x00000019)
    # KW = new(0x00000006)
    # LO = new(0x00000080)
    # DT = new(0x00000040)
    # WP = new(0x00000020)
    # RP = new(0x00000010)
    # SW = new(0x00000008)
    # LC = new(0x00000004)
    # DC = new(0x00000002)
    # CC = new(0x00000001)
    VALUES = constants
             .reject { |x| x == :VALUES }
             .map { |c| type = const_get(c); type.name = c.to_s; [type.value, type] }
             .to_h

    def to_s
      name
    end
  end

  ##
  # An ACCESS_MASK that specifies the user rights allowed by @ACE.
  #
  # @see https:#msdn.microsoft.com/en-us/library/cc230289.aspx
  ##
  class AceRights
    ##
    # Custom/Other rights.
    ##
    attr_accessor :others

    ##
    # Standard ACE rights.
    ##
    attr_reader :rights

    ##
    # Default constructor.
    ##
    def initialize(rights = [])
      @others = 0
      @rights = rights
    end

    ##
    # Parse ACE rights.
    #
    # @param value int value representing rights.
    # @return ACE rights.
    ##
    def self.parse_value(value)
      res = new
      return res if value.zero?

      res.others = value

      ObjectRight::VALUES.keys.each do |type|
        if (value & type) == type
          res.rights << ObjectRight::VALUES[type]
          res.others ^= type
        end
      end

      res
    end

    ##
    # Gets rights as unsigned int.
    #
    # @return rights as unsigned int.
    ##
    def as_uint
      res = others

      rights.each { |right| res += right.value }

      res
    end

    # The simple read is a collection of 3 other permissions
    READ = parse_value(0x20014)
    PROTECT_FROM_DELETION = parse_value(0x10040) # DELETE & DELETE_TREE
  end
end
