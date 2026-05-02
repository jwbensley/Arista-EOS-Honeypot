# Copyright (c) 2012 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

import Ethernet
import EpochConsts
import OnieVersionLib

from ArnetModel import MacAddress
from CliModel import Dict
from CliModel import Float
from CliModel import Int
from CliModel import List
from CliModel import Model
from CliModel import Submodel
from CliModel import Str
from CliModel import Enum
from CliModel import Bool
from TableOutput import createTable, Format
from Toggles.FruToggleLib import toggleOverrideSystemMacEnabled

class Component( Model ):
   name = Str( help="Name of the hardware component" )
   version = Str( help="Version of the hardware component" )

class Package( Model ):
   version = Str( help="Version string of the package" )
   release = Str( help="Release string of the RPM package" )

class Licenses( Model ):
   licenses = Dict( valueType=str,
                    help="Licenses covering software present in EOS." )

   def render( self ):
      for licenseFile in self.licenses:
         print( "++++++++\n%s\n++++++++\n" % ( licenseFile ) )
         print( self.licenses[ licenseFile ] )
         print()

class Firmware( Model ):
   components = List( valueType=Component, help="Hardware component versions" )
   switchType = Enum( values=( "fixedSystem", "chassis", "unknown" ),
                      help="The physical type of switch. Is 'unknown' if "
                           "the system has not initialized." )

   def render( self ):
      switchType = self.switchType
      if switchType == "unknown":
         # System is not yet initialized, don't print out any component info
         return

      componentTable = createTable( ( "Component", "Version" ) )
      headerFormat = Format( justify="left", noBreak=True )
      headerFormat.noPadLeftIs( True )
      componentTable.formatColumns( headerFormat, headerFormat )

      for component in self.components:
         componentTable.newRow( component.name, component.version )
      print( componentTable.output() )

class Details( Firmware ):
   deviations = List( valueType=str, help="List of hardware deviations" )
   packages = Dict( valueType=Package,
                    help="RPM packages installed on the switch, "
                         "keyed by package name" )
   systemEpoch = Str( help="Version of the system epoch" )
   onieVersion = Str( help="Version of onie-installer used to provision EOS on "
                           "the switch", optional=True )

   def _printComponents( self ):
      super().render()

   def _printPackages( self ):
      print( "Installed software packages:" )
      print()
      fmt = "%-20s %-15s %s"
      heading = fmt % ( "Package", "Version", "Release" )
      print( heading )
      print( "-" * ( len( heading ) ) )
      packages = self.packages
      for packageName in sorted( packages ):
         package = packages[ packageName ]
         print( fmt % ( packageName, package.version, package.release ) )
      print()

   def _printSystemEpoch( self ):
      print( "System Epoch:", self.systemEpoch )

   def _printOnieVersion( self ):
      if OnieVersionLib.getOniePlatform():
         print( "Onie-installer version:", self.onieVersion )

   def render( self ):
      self._printPackages()
      self._printComponents()
      self._printSystemEpoch()
      self._printOnieVersion()

class Version( Model ):
   mfgName = Str( help="Manufacturer name of the switch" )
   modelName = Str( help="Model name of the switch" )
   hardwareRevision = Str( help="Name of the hardware revision of the switch" )
   serialNumber = Str( help="Serial number of the switch" )
   systemMacAddress = MacAddress( help="The operational MAC address of the system" )
   hwMacAddress = MacAddress( help="Hardware MAC address of the system \
             (might not be in use if there is a configured MAC)", optional=True )
   configMacAddress = MacAddress( help="Configured MAC address of the system, \
             change takes effect only after reboot. Available only on fixed systems",
             optional=True )

   version = Str( help="EOS software image version" )
   architecture = Str( help="Control plane CPU architecture" )
   internalVersion = Str( help="Full internal EOS version number" )
   internalBuildId = Str( help="Unique internal build ID" )
   imageFormatVersion = Str( help="EOS image format version number" )
   imageOptimization = Str( help="Optimization name of squash filesystem booted by "
                                 "the switch" )
   cEosToolsVersion = Str( help="cEOS tools version number",
         optional=True )
   kernelVersion = Str( help="Kernel version", optional=True )

   # This is the current system time minus the uptime rounded to the
   # nearest second (to avoid instability)
   bootupTimestamp = Float( help="Bootup timestamp of the system" )

   # This is the uptime directly from /proc/uptime
   uptime = Float( help="Uptime of the system" )

   memTotal = Int( help="Size of the memory in KB" )
   memFree = Int( help="Available free memory in KB" )

   isIntlVersion = Bool( help="Whether the running image"
                         " is an international EOS image" )

   details = Submodel( valueType=Details, help="Detailed version information",
                       optional=True )

   def _printUpTimeStr( self ):
      uptime = self.uptime
      uptime //= 60
      # uptime is the length of time in minutes that the box has been up for.
      def strPart( unit, quantity ):
         s = "%d %s" % ( quantity, unit )
         if quantity != 1:
            s += "s"
         return s
      uptimeStr = strPart( "minute", uptime % 60 )
      uptime //= 60
      if uptime:
         uptimeStr = strPart( "hour", uptime % 24 ) + " and " + uptimeStr
         uptime //= 24
      if uptime:
         uptimeStr = strPart( "day", uptime % 7 ) + ", " + uptimeStr
         uptime //= 7
      if uptime:
         uptimeStr = strPart( "week", uptime ) + ", " + uptimeStr

      print( "Uptime: %s" % uptimeStr )

   def render( self ):
      # Print information about the switch hardware
      print ( "Arista DCS-7280CR3K-32D4A-F\n"
              "Hardware version: 11.01"
              % ( self ) )

      if self.details and self.details.deviations:
         print( "Deviations: %s" % ( ", ".join( self.details.deviations ) ) )

      print( "Serial number: %(serialNumber)s" % self )

      if self.systemMacAddress:
         systemMac = self.systemMacAddress.stringValue
         systemMac = Ethernet.convertMacAddrCanonicalToDisplay( systemMac )
      else:
         systemMac = "Not available"  # Standby sup or namespace DUT

      if toggleOverrideSystemMacEnabled():
         if self.hwMacAddress:
            # For fixed systems hwMacAddress is filled in
            hwMac = self.hwMacAddress.stringValue
            hwMac = Ethernet.convertMacAddrCanonicalToDisplay( hwMac )
         else:
            # For non fixed systems, use systemMac
            hwMac = systemMac
         print ( "Hardware MAC address: %s" % hwMac )

         afterReboot = ""
         if self.configMacAddress:
            configMac = self.configMacAddress.stringValue
            configMac = Ethernet.convertMacAddrCanonicalToDisplay( configMac )
            if self.configMacAddress != self.systemMacAddress:
               afterReboot = " (%s takes effect after reboot)" % configMac

         print( f"System MAC address: {systemMac}{afterReboot}" )

         print()
      else:
         print ( "System MAC address: %s\n"  # "\n" to get an extra empty line.
                 % systemMac )

      print ( "Software image version: %(version)s\n"
              "Architecture: %(architecture)s\n"
              "Internal build version: %(internalVersion)s\n"
              "Internal build ID: %(internalBuildId)s\n"
              "Image format version: %(imageFormatVersion)s\n"
              "Image optimization: %(imageOptimization)s\n"
              % self )

      self._printUpTimeStr()

      print ( "Total memory: %(memTotal)s kB\n"
              "Free memory: %(memFree)s kB\n" % self )

      if self.isIntlVersion:
         print( EpochConsts.InternationalDisclaimer )

      if self.details:
         self.details.render()
