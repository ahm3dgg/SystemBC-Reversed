#include "plugin.h"
#include <fstream>

static bool GetLabelAtAddress(duint address, char* label)
{
    bool result = false;
    size_t max_instructions = 1000;
    size_t i = 0;
    duint original_address = address;
    duint modbase = DbgFunctions()->ModBaseFromAddr(address);

    while (i < max_instructions)
    {
        BASIC_INSTRUCTION_INFO biif{};
        duint target = DbgGetBranchDestination(address);

        if (target)
        {
            duint target_modbase = DbgFunctions()->ModBaseFromAddr(target);

            if (target_modbase && target_modbase != modbase)
            {
                result = DbgGetLabelAt(target, SEG_DEFAULT, label);
                break;
            }

            address = target;
        }
        else
        {
            DbgDisasmFastAt(address, &biif);
            address += biif.size;
        }

        i += 1;
    }

    return result;
}

static bool ResolveAPI(int argc, char** argv)
{ 
    std::ofstream file("apis.txt");

    if (argc < 2)
    {
        dprintf("Usage " PLUGIN_NAME " <start> <end - optional>");
        return false;
    }

    duint start = DbgEval(argv[1]);
    if (argc == 2)
    {
        char label[MAX_LABEL_SIZE] = { 0 };
        GetLabelAtAddress(start, label);
        DbgSetLabelAt(start, label);
    }
    else
    {
        duint end = DbgEval(argv[2]);
        
        if (end < start)
        {
            dprintf("End address should be larger than Start Address");
            return false;
        }

        duint address = start;

        while (address <= end)
        {
            BASIC_INSTRUCTION_INFO biif = {};
            dprintf("Scanning from: %p\n", address);

            for (;;)
            {
                uint8_t opcode;
                DbgDisasmFastAt(address, &biif);

                if (biif.branch && !biif.call && DbgMemRead(address, &opcode, 1) && opcode == 0xE9)
                {
                    dprintf("Jump at -> %p\n", address);
                    break;
                }

                address += 1;
            }

            char label[MAX_LABEL_SIZE] = {};
            if (GetLabelAtAddress(address, label))
            {
                dprintf("Label -> %s\n", label);
                duint addrefd = address;

                while (!DbgGetXrefCountAt(addrefd))
                {
                    addrefd -= 1;
                }

                // <ea>,label
                char line[1024] = { 0 };
                sprintf(line, "%016llX,%s", (uint64_t)addrefd, label);
                file << line << "\n";
                DbgSetLabelAt(addrefd, label);
            }

            address += biif.size;
        }
    }

    return true;
}

bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);
    _plugin_registercommand(pluginHandle, PLUGIN_NAME, ResolveAPI, true);
    return true;
}

void pluginStop()
{
    dprintf("pluginStop(pluginHandle: %d)\n", pluginHandle);
}

void pluginSetup()
{
    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}
