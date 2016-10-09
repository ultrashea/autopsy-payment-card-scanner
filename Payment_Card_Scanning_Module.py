#   Copyright 2016 Shea Nangle
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# Contact: Shea Nangle [shea [dot] nangle <at> gmail [dot] com]
import jarray
import inspect
import re
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.apache.commons.io import IOUtils
from java.nio.charset import StandardCharsets

class PaymentCardFileIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "Payment Card Scanning Module"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Ingest module that scans for possible payment card numbers (credit cards, debit cards, etc)"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return PaymentCardFileIngestModule()



class PaymentCardFileIngestModule(FileIngestModule):
    _logger = Logger.getLogger(PaymentCardFileIngestModuleFactory.moduleName)
    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        self.filesFound = 0
        # This process tends to report a large number of files with numeric sequences
        # that are Luhn checksum-valid but are not payment card numbers.  By default,
        # We only scan text files.  If you want to scan binary files as well, set
        # self.skipBinaries to 1.  Additionally, numbers in binary files such as 
        # spreadsheet files may not be detected.  A possible solution is to incorporate 
        # parsing code for specific document types.
        self.skipBinaries = 1
        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException(IngestModule(), "Oh No!")
        pass

    def process(self, file):
        def luhnChecksumIsValid(cardNumber):
        # check to make sure that the card passes a luhn mod-10 checksum
            total = 0
            oddTotal = 0
            evenTotal = 0
            reversedCardNumber = cardNumber[::-1]
            oddDigits = reversedCardNumber[0::2]
            evenDigits = reversedCardNumber[1::2]
            for count in range(0,len(oddDigits)):
                oddTotal += int(oddDigits[count])
            for count in range(0,len(evenDigits)):
                evenDigit = int(evenDigits[count])
                evenDigit = evenDigit * 2
                if evenDigit > 9:
                    evenDigit = evenDigit - 9
                evenTotal += evenDigit
            total = oddTotal + evenTotal
            return(total%10==0)
        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or 
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or 
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK
        inputStream = ReadContentInputStream(file)
        text = IOUtils.toString(inputStream, StandardCharsets.UTF_8)
        if self.skipBinaries:
            if b'\x00' in text:
               return IngestModule.ProcessResult.OK 
        initialCCPattern = '[1-6](?:\d[ -]*?){13,23}'
        possibleCCs = re.findall(initialCCPattern, text, re.IGNORECASE)
        self.fileFlagged = 0
        if possibleCCs:
            for cc in possibleCCs:
                delim_regex = "\D+"
                cc = re.sub(delim_regex,'',cc)
                if luhnChecksumIsValid(cc):
                    if self.fileFlagged == 0:
                        self.filesFound += 1
                        art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
                        att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), PaymentCardFileIngestModuleFactory.moduleName, "Files With Possible Payment Card Numbers")
                        art.addAttribute(att)  
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(PaymentCardFileIngestModuleFactory.moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));
                        self.fileFlagged = 1
        return IngestModule.ProcessResult.OK

    def shutDown(self):
        if self.filesFound:
            message = IngestMessage.createMessage(
                IngestMessage.MessageType.DATA, PaymentCardFileIngestModuleFactory.moduleName, str(self.filesFound) + " file(s) found with possible payment card numbers")
            ingestServices = IngestServices.getInstance().postMessage(message)
