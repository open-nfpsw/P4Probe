//***************NETRONOME WEBINAR SERIES REFERENCE CODE-WEBINAR 1-P4Probe**********************
/*
By Nic Viljoen, Netronome Systems

This is a strawman app P4/C probing app.

This is the C sandbox plugin for the P4 probe app, please note this is the original (but cleaned up) code and is not yet optimised.
There are some simple optimisations, such as finding the method for finding the interarrival time bucket that can
still be added.

Also note that currently I am only using the lower 32 bits of the timestamp, this can lead to wrapping. 
Adding the top 8 bits of the timestamp will ensure this is avoided

Note also that this code is not optimised, in fact there are a number of bad practices currently being used.
These will be pointed out with ***OPTIMIZATION*** in this file.

I hope to release an optimized version of this code at some point in the near future (if I have time).

I also have not had time to test this code in its very final cleaned up form extensively. It is highly possible some
creepy crawly has snuck in. 

***The first reference you should use to understand the architecture of the chip and this C plugin code is 'The Joy of
Micro C' which gives a very good overview of the architecture***

This document is to be found at http://open-nfp.org/media/pdfs/the-joy-of-micro-c.pdf

***If you are having trouble please feel free to contact me at nick.viljoen at netronome.com***

*/

//headers: Note some of these may now be redundant due to changes in code-I have not yet tidied this up

#include <pif_plugin.h>
#include <nfp.h>
#include <stdint.h>
#include <nfp6000/nfp_me.h>
#include "flow_cache_global_c.h"
#include "flow_cache_timestamp_c.h"
#include <mem_atomic_indirect_c.h>
#include <nfp/mem_atomic.h>


#define IP_ADDR(a, b, c, d) ((a << 24) | (b << 16) | (c << 8) | d)

//optimise for your usecase-note not used as mask in current implementation
#define BUCKET0 0xFFFFFFF
#define BUCKET1 0x2FFFFFFF
#define BUCKET2 0x4FFFFFFF
#define BUCKET3 0x6FFFFFFF
#define BUCKET4 0x8FFFFFFF
#define BUCKET5 0xAFFFFFFF
#define BUCKET6 0xCFFFFFFF

 


__shared volatile uint32_t mciothist[8]; //histogram of mission critical IOT interarrival times
__shared volatile uint32_t voicecounter; //voice traffic packet counter
__shared volatile uint32_t voicelarge; //large packets counter-used to check for anomalies in voice traffic
__shared volatile uint32_t nciotcounter; // non-critical IOT packet counter-check that there is not excessive traffic from these sources-could violate SLA 
__shared volatile uint32_t allcounter; //check for total packet count
__shared volatile uint32_t mciotprev; //this keeps track of the previous


// the __shared indicates that the values are stored in shared memory which is accessible to all the MEs
// the volatile indicates that the compiler should not try to optimise this


int pif_plugin_filter_func(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *data)
{

   //----------------------------Header Extract----------------------------------

    PIF_PLUGIN_vslice_T *vslice;        // Note that the PIF_PLUGIN_vslice_T is automatically added to pif_plugin.h when defined in P4

    PIF_PLUGIN_ipv4_T *ipv4;            

    vslice = (PIF_PLUGIN_vslice_T*) pif_plugin_hdr_get_vslice(headers); //assign vslice header

    ipv4 = (PIF_PLUGIN_ipv4_T*) pif_plugin_hdr_get_ipv4(headers); //assign ipv4 header


    //----------------Start Slice Match and Actions-Note Inlining---------------------
 
    allcounter++; //increment all packets counter


    //----------------Slice 0------------------------------------

    /***Timestamp histogram algorithm***

    Please note this is a strawman algorithm and not efficient or correct-for reasons I will explain below.
    Currently there are two stages:

    1. Find the inter arrival time
        This is done using the timestamp within the flow cache

    2. Find the correct Histogram bucket

    ***Important 1***

    Due to the highly parallel nature of the nfp, there is a possibility of Timestamps being processed slightly 
    out of order-therefore it is essential that if planning on using this type of code at high data rates in 
    real usecases a sanity check is done to ensure that negative values arent accidentally used for timestamp 
    deltas.

    If the objective is to find significant jitter this should still be useful as the effect the reordering 
    will have on timestamp_delta will not be significant in this case. 

    ***Important 2***

    Currently the timestamp_delta for this demo code are calculated assuming that the slice is a single flow
    to ensure that the timestamps are flow specific you can reuse the timestamp from the flow cache as then
    you dont require a new hash-checkout flow_cache.c if you want to follow this path. I would hope at some 
    point to be able to build this into this demo (If I ever get time!)

    */


    if (vslice->slice == 0) {
        //defining a variable as a __gpr variable means the compiler will bput them into the general purpose registers (gpr)
        __gpr uint32_t mciotprevlocal; //local variable to hold the previous timestamp
        __gpr uint32_t timestamp_low;   //timestamp containing lower 32 bits of current timestamp
        __xwrite uint32_t writetimedelta; //write transfer register (__xwrite) to pass value through atomic write to mciotprev store
        __ctm uint32_t  timestamp_delta; // variable stored in __ctm to hold timestamp delta ***OPTIMIZATION*** place this within the gpr
        __ctm uint8_t bucketspace; //this holds the bucket to be incremented in the histogram ***OPTIMIZATION*** to gpr
        timestamp_low = local_csr_read(local_csr_timestamp_low);//this is the function to gather the lower bits of the timestamp
		local_csr_write(local_csr_mailbox1, timestamp_low); //data watches CANNOT be set on gpr variables-therefore to monitor these use mailboxes-this is demonstrated in webinar video
		

        if (mciotprev == 0) //ensure that first packet sets up later comparisons-again this state machine may have to be slightly heavier for multiple flows
        {
            writetimedelta = timestamp_low;
            mem_write_atomic(&writetimedelta, (__mem void*)&mciotprev, sizeof(uint32_t));
            return PIF_PLUGIN_RETURN_FORWARD; //forward packet on to next P4 action
        }
        else //find timestamp delta
        {
            mciotprevlocal = mciotprev;
            timestamp_delta = timestamp_low - mciotprevlocal;
            local_csr_write(local_csr_mailbox0, mciotprevlocal);//mailbox writes for debugging-use breakpoints and ensure that the mailbox values and final result make sense
			local_csr_write(local_csr_mailbox2, timestamp_delta);
            writetimedelta = timestamp_delta;
            mem_write_atomic(&writetimedelta, (__mem void*)&mciotprev, sizeof(uint32_t));

            //***OPTIMIZATION*** Use sensible bit masks to reduce cycles used on comparisons below-current implementation is easy to follow but inefficient
            if (timestamp_delta < BUCKET0) 
            {
                mciothist[0]++; //increment correct bucket
                return PIF_PLUGIN_RETURN_FORWARD;
            }
            if (timestamp_delta > BUCKET0)
            {
                if (timestamp_delta < BUCKET1)
                {
                    mciothist[1]++;
                    return PIF_PLUGIN_RETURN_FORWARD;
                }
                
            }
            if (timestamp_delta > BUCKET1)
            {
                if (timestamp_delta < BUCKET2)
                {
                    mciothist[2]++;
                    return PIF_PLUGIN_RETURN_FORWARD;
                }
                
            }
            if (timestamp_delta > BUCKET2)
            {
                if (timestamp_delta < BUCKET3)
                {
                    mciothist[3]++;
                    return PIF_PLUGIN_RETURN_FORWARD;
                }
                
            }
            if (timestamp_delta > BUCKET3)
            {
                if (timestamp_delta < BUCKET4)
                {
                    mciothist[4]++;
                    return PIF_PLUGIN_RETURN_FORWARD;
                }
                
            }
            if (timestamp_delta > BUCKET4)
            {
                if (timestamp_delta < BUCKET5)
                {
                    mciothist[5]++;
                    return PIF_PLUGIN_RETURN_FORWARD;
                }
                
            }
            if (timestamp_delta > BUCKET5)
            {
                if (timestamp_delta < BUCKET6)
                {
                    mciothist[6]++;
                    return PIF_PLUGIN_RETURN_FORWARD;
                }
                
            }
            mciothist[7]++;
            return PIF_PLUGIN_RETURN_FORWARD;
        }
        

    }

    //--------------------------Slice 1--------------------------------------------

    /***Simple Monitoring***

    In This example we use counters to keep state, we are observing the number of large packets as this
    could be a harbringer of some issue in voice traffic

    */
    if (vslice->slice == 1)
    {
        __gpr uint32_t packetsize; //sizes
        packetsize = ipv4->len;
        voicecounter++;
        if (packetsize > 1450)
        {
            voicelarge++; 
        }
        if (voicecounter > 1000)
        {
            voicelarge = 0;
        }       

        return PIF_PLUGIN_RETURN_FORWARD;
     }
    
    //-----------------------------Slice 2---------------------------------

    /***Simple Monitoring + Reaction***

    In this example if there is a significant amount of non-critical IOT traffic relative to 
    other traffic we could be seeing a DDOS style attack or someone violating their SLA 
    therefore we start dropping packets from this slice (and this slice only)

    */

    if (vslice->slice == 2)
    {
        nciotcounter++;
        if (allcounter > 10000)
        {
            nciotcounter = 0;
        }
        if (nciotcounter > 1000) 
        {
            return PIF_PLUGIN_RETURN_DROP;
        }  
        return PIF_PLUGIN_RETURN_FORWARD;
    }
    //-------------------------Unknown Handling------------------------------
    else
    {
        local_csr_write(local_csr_mailbox0, vslice->slice); //write debug to mailbox
        return PIF_PLUGIN_RETURN_DROP;  //drop packet
    }



}



    
    

