# Copyright (c) 2006-2010, 2011 Arista Networks, Inc.  All rights reserved.
# Arista Networks, Inc. Confidential and Proprietary.

from collections import namedtuple
import io
import json
import tempfile

import CliCommon
import CliDiff
import ShowRunOutputModel
import Tac
import Tracing
from CliDiff import DiffModel

th = Tracing.defaultTraceHandle()
trace = th.trace0
traceTopSort = th.trace1
traceDetail = th.trace2
traceDiff = th.trace3

# Marker for commands that we want to skip saving.
SKIP_COMMAND_MARKER = '\xff'

ShowRunningConfigOptions = namedtuple( 'option', [ 'saveAll',
                                                   'saveAllDetail',
                                                   'showNoSeqNum',
                                                   'secureMonitor',
                                                   'commandTag',
                                                   'showProfileExpanded',
                                                   'showFilteredRoot',
                                                   'intfFilter',
                                                   'expandMergeRange' ] )
ShowRunningConfigOptions.__new__.__defaults__ = ( False, # saveAll
                                                  False, # saveAllDetail
                                                  False, # showNoSeqNum
                                                  False, # secureMonitor
                                                  None, # commandTag
                                                  False, # showProfileExpanded
                                                  False, # showFilteredRoot
                                                  None, # intfFilter
                                                  True, # expandMergeRange
                                                 )

ShowRunningConfigRenderOptions = namedtuple( 'renderOption', [ 'showSanitized',
                                                               'showJson',
                                                               'showHeader' ] )
ShowRunningConfigRenderOptions.__new__.__defaults__ = ( False, # showSanitized
                                                        False, # showJson,
                                                        True, # showHeader
                                                        )

# -----------------------------------------------------------------------------------
# The model here is that the CLI save output comprises a set of SaveBlocks, of two
# kinds: CommandSequences and ModeCollections.  A CommandSequence comprises an
# ordered sequence of CLI commands.  A ModeCollection comprises a set of Mode
# instances, each of which recursively contains a set of SaveBlocks.
#
# SaveBlocks may have dependencies between them which are used to compute the order
# in which they are output.
#
# For examples of how to write a CliSave plugin, see AID95.
# -----------------------------------------------------------------------------------
class SaveBlock:
   """Abstract baseclass for all SaveBlocks, the basic unit from which the CLI save
   output is produced."""

   def generateSaveBlockModel( self, param ):
      """ Translate the SaveBlocks that potentially depend on Sysdb into a model
          that is completely self-contained """
      raise NotImplementedError

   def empty( self, param ):
      """ Returns True if there are no commands in this SaveBlock."""
      raise NotImplementedError

   def content( self, param ):
      """The content function returns a tuple to facilitate the range merge
      feature where multiple instances of a certain config mode (e.g., VLAN)
      can be displayed as a range if they have identical content."""
      raise NotImplementedError

sanitizedString = "<removed>"

class SensitiveCommand:
   """A command that contains both normal and sanitized output. It can be
   given to a CommandSequence."""
   __slots__ = ( 'format_', 'tokens_' )

   def __init__( self, formatStr, *tokens ):
      # Format string contains "{}" to be substituted by tokens, such as
      # "password {}". If the format string is constructed dynamically,
      # consider using CliSave.escapeFormatString() so it does not contain
      # any { or } characters.
      #
      # Note all tokens are sensitive and will be replaced by sanitizedString.
      assert not formatStr.endswith( '\n' )
      # <string>.format() doesn't care if there are more tokens, so let's
      # add a bit more sanity check. using >= to account for escaped {{}}
      # just in case.
      assert formatStr.count( '{}' ) >= len( tokens )
      self.format_ = formatStr
      self.tokens_ = tokens

   def normalOutput( self ):
      return self.format_.format( *self.tokens_ )

   def sanitizedOutput( self ):
      return self.format_.format( *( sanitizedString, ) * len( self.tokens_ ) )

   def output( self, options ):
      if options.showSanitized:
         return self.sanitizedOutput()
      return self.normalOutput()

   def __eq__( self, other ):
      return ( isinstance( other, SensitiveCommand ) and
               self.format_ == other.format_ and
               self.tokens_ == other.tokens_ )

   def __str__( self ):
      return self.format_

   def __repr__( self ):
      return f"SensitiveCommand({self.format_!r})"

class CommandSequence( SaveBlock ):
   """A SaveBlock that comprises a simple ordered sequence of CLI commands.  Commands
   may be added to the sequence via the 'addCommand' method, or via one of the
   convenience methods 'writeAttr' or 'writeBoolAttr'.

   This class should not be instantiated directly by plugins; instead, a command
   sequence name should be registered with a Mode subclass by calling
   addCommandSequence( name ) on that Mode subclass, and then a CommandSequence
   object should be obtained by doing mode[ name ] on an instance of that Mode
   subclass."""

   __slots__ = ( 'commands_', 'name_' )

   def __init__( self, name ):
      SaveBlock.__init__( self )
      self.commands_ = []
      self.name_ = name

   def generateSaveBlockModel( self, param ):
      cmds = [ c for c in self.commands_ if c != SKIP_COMMAND_MARKER ]
      return CommandSequenceModel( self.name_, cmds )

   def addCommand( self, command ):
      # make sure people don't add an empty command. This generates an empty line on
      # the running-config which is wrong
      assert command

      # make sure people don't inadvertently create empty lines by adding a \n to
      # their commands, but do allow multiline commands that have "inner carriage
      # returns" in json output format (like 'banner motd' or capi's certificates)
      if isinstance( command, str ):
         assert not command.endswith( '\n' )
      self.commands_.append( command )

   def empty( self, param ):
      return not self.commands_

   def content( self, param ):
      return tuple( self.commands_ )

class ModeCollection( SaveBlock ):
   """A SaveBlock that comprises a set of Mode instances for a particular CLI
   mode.

   This class should not be instantiated directly by plugins; instead, a child Mode
   subclass should be registered with a parent Mode subclass by calling
   addChildMode( cls ) on that parent Mode subclass, and then a ModeCollection
   object should be obtained by doing mode[ cls ] on an instance of that parent
   Mode subclass."""

   def __init__( self, modeClass ):
      # TODO: would be nice to fix this assert
      # assert issubclass( modeClass, CliSaveMode.Mode )
      SaveBlock.__init__( self )
      self.modeClass_ = modeClass
      self.modeInstanceMap_ = {}

   def content( self, param ):
      return tuple( [ ( mode.enterCmd(), saveBlock.content( mode.param_ ) )
                      for mode in self.modeInstanceMap_.values()
                      for saveBlock in mode.saveBlocks_ ] )

   def _generateModeRange( self, param ):
      # Merge modes with the same block together.
      # contentMap maps content to the first mode with unique commands.
      contentMap = {}
      # modeMap maps the first mode with unique commands to a list of
      # modes with identical content.
      modeMap = {}
      for i in sorted( self.modeInstanceMap_.values() ):
         if i.hideInactive( param ):
            continue
         if i.hideUnconnected( param ):
            continue
         if i.empty( param ):
            continue
         if not i.canMergeRange():
            modeMap[ i ] = None
            continue
         content = i.content( param )
         mode = contentMap.get( content )
         if mode:
            # we can merge
            modeMap[ mode ].append( i )
         else:
            contentMap[ content ] = i
            modeMap[ i ] = [ i ]

      saveBlockModel = ModeCollectionModel( self.modeClass_ )
      for mode in sorted( modeMap.keys() ):
         m = modeMap[ mode ]
         enterCmd = mode.enterRangeCmd( m ) if m else mode.enterCmd()
         saveBlockModel.addSaveBlockModel(
               self._generateModeSaveBlocks( param, mode, enterCmd=enterCmd ) )

      return saveBlockModel

   def _generateModeSaveBlocks( self, param, mode, enterCmd=None ):
      enterCmd = mode.enterCmd() if enterCmd is None else enterCmd
      saveBlockModel = ModeEntryModel( enterCmd, mode.comments( param ),
            mode.modeSeparator() )
      mode.expandMode( param )
      for b in mode.saveBlocks_:
         if b.empty( param ):
            continue
         saveBlockModel.addSaveBlockModel( b.generateSaveBlockModel( param ) )
      return saveBlockModel

   def generateSaveBlockModel( self, param ):
      if ( param.options.expandMergeRange and
            self.modeClass_.mergeRange and len( self.modeInstanceMap_ ) > 1 ):
         return self._generateModeRange( param )

      saveBlockModel = ModeCollectionModel( self.modeClass_ )

      # This has been perfed; please don't "simplify" w/o perfing.
      if self.modeInstanceMap_:
         for mode in sorted( self.modeInstanceMap_.values() ):
            if ( mode.hideInactive( param ) or
                 mode.hideUnconnected( param ) or
                 mode.empty( param ) ): # TODO: combine as one call?
               continue

            blocks = self._generateModeSaveBlocks( param, mode )
            saveBlockModel.addSaveBlockModel( blocks )

      return saveBlockModel

   def empty( self, param ):
      """The ModeCollection is empty (no commands) if all Modes in the collection
      are empty. Note that currently, Modes are never empty, since they always
      consist of at least their enterCmd(), but it felt wrong relying on that."""

      for i in self.modeInstanceMap_.values():
         if not i.empty( param ):
            return False
      return True

   def getOrCreateModeInstance( self, param ):
      if param not in self.modeInstanceMap_:
         if param is not None:
            assert None not in self.modeInstanceMap_, \
               "singleton instance has to use getSingletonInstance()"
         self.modeInstanceMap_[ param ] = self.modeClass_( param )
      return self.modeInstanceMap_[ param ]

   def getSingletonInstance( self ):
      # This is a special case for singleton modes that don't have keys
      # We just use a fixed key.
      if ( len( self.modeInstanceMap_ ) == 1 and
           list( self.modeInstanceMap_ )[ 0 ] is not None or
           len( self.modeInstanceMap_ ) > 1 ):
         assert False, "singleton instance has to use getSingletonInstance()"
      return self.getOrCreateModeInstance( None )

class CliMergeConflict( Exception ):
   def __init__( self, message, ancestorSaveBlock, theirSaveBlock, mySaveBlock ):
      self.message_ = message
      self.ancestorSaveBlock = ancestorSaveBlock
      self.theirSaveBlock = theirSaveBlock
      self.mySaveBlock = mySaveBlock
      super().__init__( self.message_ )

   def renderConflictMsg( self, stream, ancestorConfigName, theirConfigName,
                          myConfigName ):
      options = ShowRunningConfigOptions()
      stream.write(
            'Merge conflict detected: unable to generate merged config\n' )
      stream.write( 'Please use \'show session-config diffs\' and '
            '\'show running-config diffs session-config ancestor\' for additional '
            'information.\nSpecific conflict is printed below:\n\n' )
      ancestorFile = tempfile.NamedTemporaryFile( mode='w+' )
      theirFile = tempfile.NamedTemporaryFile( mode='w+' )
      myFile = tempfile.NamedTemporaryFile( mode='w+' )

      if self.ancestorSaveBlock:
         self.ancestorSaveBlock.render( ancestorFile, options, '' )
      if self.theirSaveBlock:
         self.theirSaveBlock.render( theirFile, options, '' )
      if self.mySaveBlock:
         self.mySaveBlock.render( myFile, options, '' )
      ancestorFile.flush()
      theirFile.flush()
      myFile.flush()
      diffs = Tac.run( [ 'diff3', '--text', '--strip-trailing-cr', '-m', '-A',
         '-L', myConfigName, '-L', ancestorConfigName, '-L', theirConfigName,
         myFile.name, ancestorFile.name, theirFile.name ], stdout=Tac.CAPTURE,
         ignoreReturnCode=True )
      stream.write( diffs )

class SaveBlockModelBase:
   def render( self, stream, options, prefix ):
      """ Print the save block to the stream """
      raise NotImplementedError

   def getRenderOutput( self, options, prefix ):
      """ Render the output instead of to a stream to a list """
      f = io.StringIO()
      self.render( f, options, prefix )
      return f.getvalue().splitlines()

   def getDiffModel( self, diffModel, options, prefix, theirModel ):
      """ Generate the DiffModel from save block diff """
      raise NotImplementedError

   def getMergedModel( self, ancestorModel, theirModel ):
      """ Generate save block model for the 'merged' config """
      raise NotImplementedError

   def generateCliModel( self, cliModel, options ):
      """ Given a cliModel this function will fill in the cliModel"""
      raise NotImplementedError

   def separator( self ):
      """ Should a separator be printed """
      raise NotImplementedError

   def name( self ):
      """ a unique identifier for this save block"""
      raise NotImplementedError

   def hasChanges( self, theirModel ):
      """ return a boolean if the saveblock has any differences """
      raise NotImplementedError

class CommandSequenceModel( SaveBlockModelBase ):
   __slots__ = ( 'commands_', 'name_' )

   def __init__( self, name, commands ):
      self.name_ = name
      self.commands_ = commands

   def _getCommand( self, command, options ):
      if isinstance( command, SensitiveCommand ):
         return command.output( options )
      else:
         return command

   def getCommands( self, options ):
      # return a generator
      return ( self._getCommand( c, options ) for c in self.commands_ )

   def render( self, stream, options, prefix ):
      if "zzz" in prefix:
         return

      skip = False
      for cmd in self.getCommands( options ):
         for line in cmd.split( '\n' ):
            if "zzz" in cmd:
               skip = True
               break
      if skip:
         return
 
      for cmd in self.getCommands( options ):
         for line in cmd.split( '\n' ):
            #################################              print(f"{__file__}: CommandSequenceModel.render(): writing line '{line}' with prefix '{prefix}'")
            stream.write( f'{prefix}{line}\n' )

   def getDiffModel( self, diffModel, options, prefix, theirModel ):
      assert isinstance( theirModel, CommandSequenceModel )
      assert self.name() == theirModel.name()

      def filterFunc( tag, line ):
         # We don't care lines that don't have a change
         return tag != DiffModel.COMMON

      CliDiff.diffLines(
         diffModel,
         list( theirModel.getCommands( options ) ),
         list( self.getCommands( options ) ),
         prefix=prefix, filterFunc=filterFunc )

   def getMergedModel( self, ancestorModel, theirModel ):
      cmds = None

      if self.hasChanges( theirModel ):
         # this means that myModel and theirModel differ. If both models differ
         # from ancestor config then that's an error. However if only 1 differs
         # then take that one.
         if ( self.hasChanges( ancestorModel ) and
              theirModel.hasChanges( ancestorModel ) ):
            # this means that myConfig != theirConfig != ancestorConfig
            # raise an exception
            raise CliMergeConflict( 'Merge conflict in Command Sequences',
                  ancestorModel, theirModel, self )
         elif self.hasChanges( ancestorModel ):
            # this means that myConfig != ancestorConfig, however
            # theirConfig == ancestorConfig so print myConfig as the
            # authoritative one.
            cmds = self.commands_
         elif theirModel.hasChanges( ancestorModel ):
            # this means that theirConfig != ancestorConfig, however
            # myConfig == ancestorConfig so print theirConfig as the
            # authoritative one.
            cmds = theirModel.commands_
         else:
            assert False, 'How did we get here'
      else:
         # this means that theirModel and myModel are the same, so the ancestor
         # config doesn't matter
         cmds = self.commands_

      assert cmds is not None, 'cmds should be set'
      return CommandSequenceModel( self.name_, list( cmds ) )

   def hasChanges( self, theirModel ):
      return self.commands_ != theirModel.commands_

   def generateCliModel( self, cliModel, options ):
      for command in self.getCommands( options ):
         cliModel.cmds[ command ] = None

   def separator( self ):
      return False

   def name( self ):
      return self.name_

class ModeModelBase( SaveBlockModelBase ):
   __slots__ = ( 'saveBlocks_', )

   def __init__( self ):
      self.saveBlocks_ = []

   def render( self, stream, options, prefix ):
      firstTime = True
      prevNeedSeparator = False
      for saveBlock in self.saveBlocks_:
         #################################              print(f"{__file__}: ModeModelBase.render(): rendering save block {saveBlock} with prefix '{prefix}'")
         needSeparator = saveBlock.separator()

         if self.printSeparator( prefix, firstTime, needSeparator,
               prevNeedSeparator ):
            stream.write( f'{prefix}!\n' )
         firstTime = False
         prevNeedSeparator = needSeparator
         saveBlock.render( stream, options, prefix )

   def generateCliModel( self, cliModel, options ):
      """ Given a cliModel this function will fill in the cliModel"""
      raise NotImplementedError

   def separator( self ):
      """ Should a separator be printed """
      raise NotImplementedError

   def name( self ):
      """ a unique identifier for this save block"""
      raise NotImplementedError

   def _getMergedSaveBlocks( self, ancestorModel, theirModel ):
      mergedSaveBlocks = []
      ancestorSaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in ancestorModel.saveBlocks_ }
      mySaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in self.saveBlocks_ }
      theirSaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in theirModel.saveBlocks_ }

      saveBlockDiff = DiffModel()
      CliDiff.diffLines(
         saveBlockDiff,
         [ saveBlock.name() for saveBlock in theirModel.saveBlocks_ ],
         [ saveBlock.name() for saveBlock in self.saveBlocks_ ] )
      for tag, name in saveBlockDiff.blocks_:
         name = name[ 0 ]
         ancestorBlock = ancestorSaveBlocks.get( name )
         mySaveBlock = mySaveBlocks.get( name )
         theirSaveBlock = theirSaveBlocks.get( name )

         if tag == DiffModel.REMOVE:
            assert mySaveBlock is None
            assert theirSaveBlock is not None
            # This means that that my save block was removed. Don't print out
            # myconfig. To figure out if you want print out theirSaveBlock
            # see if it's different than ancestorSaveConfig.
            if ancestorBlock is None:
               # this means that mySaveBlock and ancestorSaveBlock don't
               # exist. This means that theisSaveBlock was added cleanly
               # so render theirSaveBlock
               mergedSaveBlocks.append( theirSaveBlock )
            elif theirSaveBlock.hasChanges( ancestorBlock ):
               # this means that mySaveBlock removed this saveBlock, and
               # theirSaveBlock modified the saveblock. This an error
               raise CliMergeConflict(
                     'Merge conflict: My config removed save block modified by '
                     'their config', ancestorBlock, theirSaveBlock, mySaveBlock )
            else:
               # this means that ancestorBlock is the same as theirSaveBlock. This
               # means that myConfig removed this config, so don't print anything
               pass

         elif tag == DiffModel.ADD:
            assert mySaveBlock is not None
            assert theirSaveBlock is None
            # this means that theirSaveBlock was removed. Don't print out
            # theirSaveBlock. To figure out if we want to print out mySaveBlock
            # see how it's different from ancestorSaveConfig.
            if ancestorBlock is None:
               # this mean that this saveblock didn't exist before and
               # myConfig added this. Just render the new saveblock!
               mergedSaveBlocks.append( mySaveBlock )
            elif mySaveBlock.hasChanges( ancestorBlock ):
               # this means that theirConfig deleted this save block
               # while myconfig modified. This is an error
               raise CliMergeConflict(
                     'Merge conflict: Their config removed save block modified by '
                     'my config', ancestorBlock, theirSaveBlock, mySaveBlock )
            else:
               # this means that ancestorBlock is the same as mySaveBlock. This
               # means that myConfig removed this config, so don't print anything
               pass

         elif tag == DiffModel.COMMON:
            # mine and theirs should exist, BUT ancestorBlock may or not
            # exist
            assert mySaveBlock is not None
            assert theirSaveBlock is not None
            if ancestorBlock is None:
               # this means that mySaveBlock and theirSaveBlock indepedently
               # added this save block. If mine and theirs are the same
               # then it should be good. If they are different that means
               # it got added and are different and that's a conflict
               if mySaveBlock.hasChanges( theirSaveBlock ):
                  raise CliMergeConflict(
                        'Merge conflict: Their config and my config added a new '
                        'save block but differ',
                        ancestorBlock, theirSaveBlock, mySaveBlock )
               else:
                  # this means that mine and theirs both got added
                  # but are the same, so just print out the entire
                  # subtree
                  mergedSaveBlocks.append( mySaveBlock )
            else:
               # this means that everything is the same. Recurse down to find
               # any additional differences
               mergedSaveBlocks.append(
                     mySaveBlock.getMergedModel( ancestorBlock, theirSaveBlock ) )
      return mergedSaveBlocks

   def hasChanges( self, theirModel ):
      mySaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in self.saveBlocks_ }
      theirSaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in theirModel.saveBlocks_ }

      if set( mySaveBlocks.keys() ) != set( theirSaveBlocks.keys() ):
         # we have different set of save blocks then that's also a diff
         return True

      for mySaveBlock in mySaveBlocks.values():
         # iterate through all of the save blocks and see if and of the saveblocks
         # underneath have any changes
         theirSaveBlock = theirSaveBlocks[ mySaveBlock.name() ]
         if mySaveBlock.hasChanges( theirSaveBlock ):
            return True

      # yay there are no changes!
      return False

   def addSaveBlockModel( self, saveBlockModel ):
      self.saveBlocks_.append( saveBlockModel )

   def getDiffModel( self, diffModel, options, prefix, theirModel ):
      trace( 'getDiffModel' )
      mySaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in self.saveBlocks_ }
      trace( 'my save blocks names', list( mySaveBlocks.keys() ) )
      theirSaveBlocks = { saveBlock.name(): saveBlock
            for saveBlock in theirModel.saveBlocks_ }
      trace( 'their blocks names', list( theirSaveBlocks.keys() ) )

      firstTime = True
      prevNeedSeparator = False

      saveBlockDiff = DiffModel()
      CliDiff.diffLines(
         saveBlockDiff,
         [ saveBlock.name() for saveBlock in theirModel.saveBlocks_ ],
         [ saveBlock.name() for saveBlock in self.saveBlocks_ ] )
      for tag, name in saveBlockDiff.blocks_:
         name = name[ 0 ]
         mySaveBlock = mySaveBlocks.get( name )
         theirSaveBlock = theirSaveBlocks.get( name )

         needSeparator = ( mySaveBlock.separator()
               if mySaveBlock else theirSaveBlock.separator() )
         printSeparator = self.printSeparator( prefix, firstTime, needSeparator,
               prevNeedSeparator )

         if tag == DiffModel.REMOVE:
            # myConfig has remove this mode
            assert mySaveBlock is None
            assert theirSaveBlock is not None

            if printSeparator:
               diffModel.append( DiffModel.REMOVE, f'{prefix}!' )
            # All ModeEntryModel must call append() with a list of lines
            if isinstance( theirSaveBlock, ModeEntryModel ):
               diffModel.append( DiffModel.REMOVE,
                                 theirSaveBlock.getRenderOutput( options, prefix ) )
            elif isinstance( theirSaveBlock, ModeCollectionModel ):
               for childMode in theirSaveBlock.saveBlocks_:
                  # Only ModeEntryModel can be in ModeCollectionModel
                  assert isinstance( childMode, ModeEntryModel )
                  diffModel.append( DiffModel.REMOVE,
                                    childMode.getRenderOutput( options, prefix ) )
            elif isinstance( theirSaveBlock, CommandSequenceModel ):
               for subline in theirSaveBlock.getRenderOutput( options, prefix ):
                  diffModel.append( DiffModel.REMOVE, subline )
            else:
               assert False

         elif tag == DiffModel.ADD:
            # myConfig has added this mode
            assert mySaveBlock is not None
            assert theirSaveBlock is None

            if printSeparator:
               diffModel.append( DiffModel.ADD, f'{prefix}!' )
            diffModel.append( DiffModel.ADD,
                              mySaveBlock.getRenderOutput( options, prefix ) )

         elif tag == DiffModel.COMMON:
            # both modes exist so lets recurse down and try to find
            # differences
            assert mySaveBlock is not None
            assert theirSaveBlock is not None
            if not mySaveBlock.hasChanges( theirSaveBlock ):
               continue
            if printSeparator:
               diffModel.append( DiffModel.COMMON, f'{prefix}!' )

            mySaveBlock.getDiffModel( diffModel, options, prefix, theirSaveBlock )
         else:
            assert False

         firstTime = False
         prevNeedSeparator = needSeparator

   def printSeparator( self, prefix, firstTime, saveBlockSeparator,
         prevNeedSeparator ):
      raise NotImplementedError

class ModeCollectionModel( ModeModelBase ):
   __slots__ = ( 'modeClass_', )

   def __init__( self, modeClass ):
      super().__init__()
      self.modeClass_ = modeClass

   def addSaveBlockModel( self, saveBlockModel ):
      # A Mode collection can only contain modes
      assert not isinstance( saveBlockModel,
            ( ModeCollectionModel, CommandSequenceModel ) )
      assert isinstance( saveBlockModel, ModeEntryModel )

      # call the base class
      super().addSaveBlockModel( saveBlockModel )

   def getMergedModel( self, ancestorModel, theirModel ):
      """ Generate save block model for the 'merged' config """
      result = ModeCollectionModel( self.modeClass_ )
      for saveBlock in self._getMergedSaveBlocks( ancestorModel, theirModel ):
         result.addSaveBlockModel( saveBlock )
      return result

   def printSeparator( self, prefix, firstTime, saveBlockSeparator,
         prevNeedSeparator ):
      # Write a newline to separate this instance of the Mode subclass
      # from the previous instance in the ModeCollection.
      return not firstTime and ( prevNeedSeparator or saveBlockSeparator )

   def generateCliModel( self, cliModel, options ):
      for saveBlock in self.saveBlocks_:
         saveBlock.generateCliModel( cliModel, options )

   def separator( self ):
      return True

   def name( self ):
      return '%s-%d' % ( self.modeClass_, id( self.modeClass_ ) )

class ModeEntryModel( ModeModelBase ):
   __slots__ = ( 'enterCmd_', 'comment_', 'separator_' )

   def __init__( self, enterCmd, comment, separator ):
      super().__init__()
      self.enterCmd_ = enterCmd
      self.comment_ = comment
      self.separator_ = separator

   def addSaveBlockModel( self, saveBlockModel ):
      # A mode can't contain modes directly, but can have a ModeCollection
      # which can contain a mode
      assert not isinstance( saveBlockModel, ModeEntryModel )
      assert isinstance( saveBlockModel,
            ( ModeCollectionModel, CommandSequenceModel ) )

      # call the base class
      super().addSaveBlockModel( saveBlockModel )

   def render( self, stream, options, prefix ):
      if "zzz" in prefix:
         return

      if "zzz" in self.commentContent( prefix ):
         return

      if self.enterCmd_:
         # all mode except for the global config mode should have an enter cmd
         if "zzz" in self.enterCmd_:
            return
         stream.write( f'{prefix}{self.enterCmd_}\n' )
         prefix = '%s   ' % prefix

      for line in self.commentContent( prefix ):
         ####################                          print(f"{__file__}: ModeEntryModel.render(): writing comment line '{line}' with prefix '{prefix}'")
         stream.write( '%s\n' % line )

      super().render( stream, options, prefix )

   def getDiffModel( self, diffModel, options, prefix, theirModel ):
      if self.enterCmd_:
         # all mode except for the global config mode should have an enter cmd
         diffModel.append( DiffModel.COMMON, f'{prefix}{self.enterCmd_}' )
         prefix = '%s   ' % prefix

      # diff the comment
      myComment = self.commentContent( prefix )
      theirComment = theirModel.commentContent( prefix )
      if myComment or theirComment:
         CliDiff.diffLines( diffModel, theirComment, myComment )

      # diff all of the save blocks
      super().getDiffModel( diffModel, options, prefix, theirModel )

   def getMergedModel( self, ancestorModel, theirModel ):
      """ Generate save block model for the 'merged' config """
      ancestorComment = ancestorModel.comment_
      theirComment = theirModel.comment_
      myComment = self.comment_

      comment = None
      if myComment != theirComment:
         # if the configs are different figure out how they compare to the ancestor
         # config

         if theirComment != ancestorComment and myComment != ancestorComment:
            # this means that mine and theirs both made changes to the same
            # comment.
            raise CliMergeConflict( 'Their config and my config both made changes '
                  'to the same comment', ancestorModel, theirModel, self )

         # this means that myComment or theirComment changed, but one of them
         # is the same as the ancestorConfig. Let find out which one changed
         if theirComment != ancestorComment:
            assert myComment == ancestorComment
            # this means theirs changed so print that one
            comment = theirComment
         elif myComment != ancestorComment:
            # this means my comment changed, so print that one
            comment = myComment
         else:
            assert False, 'Which comment should we choose???'
      else:
         # this mean that mine and theirs are the same, it doesn't really matter
         # what the ancestor was if it was changed in the same way
         comment = myComment

      result = ModeEntryModel( self.enterCmd_, comment, self.separator_ )
      for saveBlock in self._getMergedSaveBlocks( ancestorModel, theirModel ):
         result.addSaveBlockModel( saveBlock )
      return result

   def commentContent( self, prefix ):
      if self.comment_:
         return [ '{}{}{}{}'.format( prefix, CliCommon.commentAppendStr, ' ', line )
                  for line in self.comment_.splitlines() ]
      return []

   def printSeparator( self, prefix, firstTime, saveBlockSeparator,
         prevNeedSeparator ):
      # Write a newline to separate it from the previous SaveBlock
      # also always print out a separetor between saveblocks for global mode
      return not firstTime and ( not prefix or saveBlockSeparator )

   def generateCliModel( self, cliModel, options ):
      if self.enterCmd_:
         newModel = ShowRunOutputModel.Mode()
         cliModel.cmds[ self.enterCmd_ ] = newModel
         cliModel = newModel
      cliModel.header = None # only global config has the header field
      cliModel.comments = ( self.comment_.splitlines()
            if self.comment_ is not None else [] )
      for saveBlock in self.saveBlocks_:
         saveBlock.generateCliModel( cliModel, options )

   def separator( self ):
      return self.separator_

   def name( self ):
      return self.enterCmd_

   def hasChanges( self, theirModel ):
      if self.comment_ != theirModel.comment_:
         # if comments aren't the same then there are changes
         return True

      # return base cls implementation
      return super().hasChanges( theirModel )

class SaveBlockModelRenderer:
   @staticmethod
   def render( stream, options, headers, rootSaveBlock ):
      if options.showJson:
         SaveBlockModelRenderer._writeJsonToStream( headers, stream, options,
                                                    rootSaveBlock )
      else:
         # write the text to the stream
         skip = False
         for header in headers:
            if "zzz" in header:
               skip = True
               break
         if skip:
            return

         for header in headers:
            #################################              print(f"{__file__}: SaveBlockModelRenderer.render(): Header {header}")
            stream.writelines( ( header, "\n!\n" ) )
         rootSaveBlock.render( stream, options, '' )
         stream.writelines( ( '!\n', 'end\n' ) )

   @staticmethod
   def _writeJsonToStream( headers, stream, options, rootSaveBlock ):
      # generate them model
      cliModel = ShowRunOutputModel.Mode()
      rootSaveBlock.generateCliModel( cliModel, options )
      cliModel.header = headers # add the header to the root

      # print the model to the stream
      stream.flush()
      # TODO: don't generate the model at all and have generateCliModel
      # actually generate json (with a name change)
      json.dump( cliModel.toDict(), stream )
      stream.flush()

   @staticmethod
   def _getDiffModel( options, theirHeaders, myHeaders,
         theirSaveBlock, mySaveBlock ):
      assert not options.showJson

      diffModel = CliDiff.DiffModel()

      if options.showHeader:
         if myHeaders != theirHeaders:
            myHeader = '\n'.join( myHeaders ).split( '\n' )
            theirHeader = '\n'.join( theirHeaders ).split( '\n' )

            def filterFunc( tag, line ):
               # skip empty lines
               return line.strip()
            CliDiff.diffLines( diffModel, theirHeader, myHeader,
                               filterFunc=filterFunc )

      mySaveBlock.getDiffModel( diffModel, options, '', theirSaveBlock )
      return diffModel

   @staticmethod
   def renderDiff( stream, options, theirHeaders, myHeaders,
         theirSaveBlock, mySaveBlock ):
      diffModel = SaveBlockModelRenderer._getDiffModel( options,
                     theirHeaders, myHeaders, theirSaveBlock, mySaveBlock )
      diffModel.render( stream )

   @staticmethod
   def renderDiffCliCommands( stream, options, theirHeaders, myHeaders,
         theirSaveBlock, mySaveBlock ):
      diffModel = SaveBlockModelRenderer._getDiffModel( options,
                     theirHeaders, myHeaders, theirSaveBlock, mySaveBlock )
      cliCommands = diffModel.getCliCommands()
      for cmd in cliCommands:
         stream.write( f'{cmd}\n' )
