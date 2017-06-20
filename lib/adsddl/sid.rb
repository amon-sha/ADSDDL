##
# Copyright (C) 2015 Tirasa (info@tirasa.net)
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##

module Adsddl
  ##
  # A security identifier (SID) uniquely identifies a security principal. Each security principal has a unique SID that
  # is issued by a security agent. The agent can be a Windows local system or domain. The agent generates the SID when
  # the security principal is created. The SID can be represented as a character string or as a structure. When
  # represented as strings, for example in documentation or logs, SIDs are expressed as follows:
  #
  # S-1-IdentifierAuthority-SubAuthority1-SubAuthority2-...-SubAuthorityn
  #
  # The top-level issuer is the authority. Each issuer specifies, in an implementation-specific manner, how many integers
  # identify the next issuer.
  #
  # A newly created account store is assigned a 96-bit identifier (a cryptographic strength (pseudo) random number).
  #
  # A newly created security principal in an account store is assigned a 32-bit identifier that is unique within the
  # store.
  #
  # The last item in the series of SubAuthority values is known as the relative identifier (RID). Differences in the RID
  # are what distinguish the different SIDs generated within a domain.
  #
  # Consumers of SIDs SHOULD NOT rely on anything more than that the SID has the appropriate structure.
  #
  # @see https:#msdn.microsoft.com/en-us/library/cc230371.aspx
  # @see https:#msdn.microsoft.com/en-us/library/gg465313.aspx
  ##
  class SID
    ##
    # An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
    ##
    attr_reader :revision

    ##
    # A SID_IDENTIFIER_AUTHORITY (6 bytes) structure that indicates the authority under which the SID was created.
    # It describes the entity that created the SID. The Identifier Authority value 0,0,0,0,0,5end denotes SIDs created
    # by the NT SID authority.
    ##
    attr_reader :identifier_authority

    ##
    # A variable length list of unsigned 32-bit integers that uniquely identifies a principal relative to the
    # IdentifierAuthority.
    ##
    attr_reader :sub_authorities

    ##
    # Instances a new SID with the given identifier authority.
    #
    # @param identifier identifier authority (6 bytes only).
    ##
    def initialize(identifier = nil, sub_authorities = [])
      @sub_authorities = sub_authorities
      @revision = 0x01
      @identifier_authority = identifier
    end

    ##
    # Instances a SID instance of the given byte array (string).
    #
    # @param src SID as byte array (string).
    # @return SID instance.
    ##
    def self.parse(src)
      sid = SID.new
      sid.parse(src, 0)
      sid
    end

    ##
    # Load the SID from the buffer returning the last SID segment position into the buffer.
    #
    # @param buff array of bytes (string).
    # @param start start loading position.
    # @return last loading position.
    ##
    def parse(buff, start)
      pos = start

      bytes = buff[pos..(pos + 8)].unpack('C*')
      pos += 8

      # Check for a SID (http://msdn.microsoft.com/en-us/library/cc230371.aspx)
      # Revision(1 byte): An 8-bit unsigned integer that specifies the revision level of the SID.
      # This value MUST be set to 0x01.
      @revision = bytes[0]

      # SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements
      # in the SubAuthority array. The maximum number of elements allowed is 15.
      auth_count = bytes[1]

      # IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the
      # authority under which the SID was created. It describes the entity that created the SID.
      # The Identifier Authority value 0,0,0,0,0,5end denotes SIDs created by the NT SID authority.
      @identifier_authority = bytes[2...8]

      # SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely
      # identifies a principal relative to the IdentifierAuthority. Its length is determined by
      # SubAuthorityCount.
      (0...auth_count).each do |_j|
        sub_authorities << buff[pos...(pos + 4)].unpack('V')[0]
        pos += 4
      end

      pos
    end

    ##
    # Gets sub-authority number: an 8-bit unsigned integer that specifies the number of elements in the SubAuthority
    # array. The maximum number of elements allowed is 15.
    #
    # @return sub-authorities number.
    ##
    def sub_authority_count
      sub_authorities.size > 15 ? 15 : sub_authorities.size
    end

    ##
    # Gets size of the SID byte array form.
    #
    # @return size of SID byte aray form.
    ##
    def size
      8 + sub_authorities.size * 4
    end

    ##
    # Serializes to byte array.
    #
    # @return serialized SID.
    ##
    def bytes
      # variable content size depending on sub authorities number
      [revision, sub_authority_count, *identifier_authority, *sub_authorities].pack('C8V*')
    end

    def ==(other)
      other.class == self.class && other.bytes == bytes
    end

    ##
    # Serializes to string.
    #
    # @return serialized SID.
    ##
    def to_s
      bld = 'S-1-'

      bld += if identifier_authority[0].zero? && identifier_authority[1].zero?
               identifier_authority[2..5].pack('C*').unpack('N')[0].to_s
             else
               identifier_authority.pack('H*').join
             end

      bld += if sub_authorities.empty?
               '-0'
             else
               '-' + sub_authorities.map(&:to_s).join('-')
             end

      bld
    end

    AUTHENTICATED_USERS = SID.new([0, 0, 0, 0, 0, 5], [11])
    EVERYONE = SID.new([0, 0, 0, 0, 0, 1], [0])
  end
end
