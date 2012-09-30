// mach_override.c semver:1.2.0
//   Copyright (c) 2003-2012 Jonathan 'Wolf' Rentzsch: http://rentzsch.com
//   Some rights reserved: http://opensource.org/licenses/mit
//   https://github.com/rentzsch/mach_override

#if !defined(__i386__) && !defined(__x86_64__)
#error The target architecture is not supported.
#endif

#include "mach_override.h"

#include <mach-o/dyld.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <sys/mman.h>

#include "libudis86/extern.h"

#include <CoreServices/CoreServices.h>

/**************************
*	
*	Constants
*	
**************************/
#pragma mark	-
#pragma mark	(Constants)

#define kPageSize 4096
#if defined(__i386__) 

#define kOriginalInstructionsSize 16
// On X86 we migh need to instert an add with a 32 bit immediate after the
// original instructions.
#define kMaxFixupSizeIncrease 5

unsigned char kIslandTemplate[] = {
	// kOriginalInstructionsSize nop instructions so that we 
	// should have enough space to host original instructions 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	// Now the real jump instruction
	0xE9, 0xEF, 0xBE, 0xAD, 0xDE
};

#define kInstructions	0
#define kJumpAddress    kInstructions + kOriginalInstructionsSize + 1
#elif defined(__x86_64__)

#define kOriginalInstructionsSize 32
// On X86-64 we never need to instert a new instruction.
#define kMaxFixupSizeIncrease 0

#define kJumpAddress    kOriginalInstructionsSize + 6

unsigned char kIslandTemplate[] = {
	// kOriginalInstructionsSize nop instructions so that we 
	// should have enough space to host original instructions 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	// Now the real jump instruction
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};

#endif

/**************************
*	
*	Data Types
*	
**************************/
#pragma mark	-
#pragma mark	(Data Types)

typedef	struct	{
	char	instructions[sizeof(kIslandTemplate)];
}	BranchIsland;

/**************************
*	
*	Funky Protos
*	
**************************/
#pragma mark	-
#pragma mark	(Funky Protos)

static mach_error_t
allocateBranchIsland(
		BranchIsland	**island,
		void *originalFunctionAddress);

	mach_error_t
freeBranchIsland(
		BranchIsland	*island );

mach_error_t
setBranchIslandTarget_i386(
						   BranchIsland	*island,
						   const void		*branchTo,
						   char*			instructions );
void 
atomic_mov64(
		uint64_t *targetAddress,
		uint64_t value );

	static Boolean 
eatKnownInstructions( 
	unsigned char	*code, 
	uint64_t		*newInstruction,
	int				*howManyEaten, 
	char			*originalInstructions,
	int				*originalInstructionCount, 
	uint8_t			*originalInstructionSizes );

	static void
fixupInstructions(
    uint32_t		offset,
    void		*instructionsToFix,
	int			instructionCount,
	uint8_t		*instructionSizes );

/*******************************************************************************
*	
*	Interface
*	
*******************************************************************************/
#pragma mark	-
#pragma mark	(Interface)

mach_error_t makeIslandExecutable(void *address) {
	mach_error_t err = err_none;
    uintptr_t page = (uintptr_t)address & ~(uintptr_t)(kPageSize-1);
    int e = err_none;
    e |= mprotect((void *)page, kPageSize, PROT_EXEC | PROT_READ | PROT_WRITE);
    e |= msync((void *)page, kPageSize, MS_INVALIDATE );
    if (e) {
        err = err_cannot_override;
    }
    return err;
}

    mach_error_t
mach_override_ptr(
	void *originalFunctionAddress,
    const void *overrideFunctionAddress,
    void **originalFunctionReentryIsland )
{
	assert( originalFunctionAddress );
	assert( overrideFunctionAddress );
	
	// this addresses overriding such functions as AudioOutputUnitStart()
	// test with modified DefaultOutputUnit project
#if defined(__x86_64__)
    for(;;){
        if(*(uint16_t*)originalFunctionAddress==0x25FF)    // jmp qword near [rip+0x????????]
            originalFunctionAddress=*(void**)((char*)originalFunctionAddress+6+*(int32_t *)((uint16_t*)originalFunctionAddress+1));
        else break;
    }
#elif defined(__i386__)
    for(;;){
        if(*(uint16_t*)originalFunctionAddress==0x25FF)    // jmp *0x????????
            originalFunctionAddress=**(void***)((uint16_t*)originalFunctionAddress+1);
        else break;
    }
#endif

	long	*originalFunctionPtr = (long*) originalFunctionAddress;
	mach_error_t	err = err_none;
	
	int eatenCount = 0;
	int originalInstructionCount = 0;
	char originalInstructions[kOriginalInstructionsSize];
	uint8_t originalInstructionSizes[kOriginalInstructionsSize];
	uint64_t jumpRelativeInstruction = 0; // JMP

	Boolean overridePossible = eatKnownInstructions ((unsigned char *)originalFunctionPtr, 
										&jumpRelativeInstruction, &eatenCount, 
										originalInstructions, &originalInstructionCount, 
										originalInstructionSizes );
	if (eatenCount + kMaxFixupSizeIncrease > kOriginalInstructionsSize) {
		//printf ("Too many instructions eaten\n");
		overridePossible = false;
	}
	if (!overridePossible) err = err_cannot_override;
	if (err) fprintf(stderr, "err = %x %s:%d\n", err, __FILE__, __LINE__);
	
	//	Make the original function implementation writable.
	if( !err ) {
		err = vm_protect( mach_task_self(),
				(vm_address_t) originalFunctionPtr, 8, false,
				(VM_PROT_ALL | VM_PROT_COPY) );
		if( err )
			err = vm_protect( mach_task_self(),
					(vm_address_t) originalFunctionPtr, 8, false,
					(VM_PROT_DEFAULT | VM_PROT_COPY) );
	}
	if (err) fprintf(stderr, "err = %x %s:%d\n", err, __FILE__, __LINE__);
	
	//	Allocate and target the escape island to the overriding function.
	BranchIsland	*escapeIsland = NULL;
	if( !err )	
		err = allocateBranchIsland( &escapeIsland, originalFunctionAddress );
		if (err) fprintf(stderr, "err = %x %s:%d\n", err, __FILE__, __LINE__);

	
        if (err) fprintf(stderr, "err = %x %s:%d\n", err, __FILE__, __LINE__);

	if( !err )
		err = setBranchIslandTarget_i386( escapeIsland, overrideFunctionAddress, 0 );
 
	if (err) fprintf(stderr, "err = %x %s:%d\n", err, __FILE__, __LINE__);
	// Build the jump relative instruction to the escape island

	if (!err) {
		uint32_t addressOffset = ((char*)escapeIsland - (char*)originalFunctionPtr - 5);
		addressOffset = OSSwapInt32(addressOffset);
		
		jumpRelativeInstruction |= 0xE900000000000000LL; 
		jumpRelativeInstruction |= ((uint64_t)addressOffset & 0xffffffff) << 24;
		jumpRelativeInstruction = OSSwapInt64(jumpRelativeInstruction);		
	}
	
	//	Optionally allocate & return the reentry island. This may contain relocated
	//  jmp instructions and so has all the same addressing reachability requirements
	//  the escape island has to the original function, except the escape island is
	//  technically our original function.
	BranchIsland	*reentryIsland = NULL;
	if( !err && originalFunctionReentryIsland ) {
		err = allocateBranchIsland( &reentryIsland, escapeIsland);
		if( !err )
			*originalFunctionReentryIsland = reentryIsland;
	}
	

	// Atomically:
	//	o If the reentry island was allocated:
	//		o Insert the original instructions into the reentry island.
	//		o Target the reentry island at the first non-replaced 
	//        instruction of the original function.
	//	o Replace the original first instructions with the jump relative.
	//
	// Note that on i386, we do not support someone else changing the code under our feet
	if ( !err ) {
		uint32_t offset = (uintptr_t)originalFunctionPtr - (uintptr_t)reentryIsland;
		fixupInstructions(offset, originalInstructions,
					originalInstructionCount, originalInstructionSizes );
	
		if( reentryIsland )
			err = setBranchIslandTarget_i386( reentryIsland,
										 (void*) ((char *)originalFunctionPtr+eatenCount), originalInstructions );
		// try making islands executable before planting the jmp
        if( !err )
            err = makeIslandExecutable(escapeIsland);
        if( !err && reentryIsland )
            err = makeIslandExecutable(reentryIsland);
		if ( !err )
			atomic_mov64((uint64_t *)originalFunctionPtr, jumpRelativeInstruction);
	}
	
	//	Clean up on error.
	if( err ) {
		if( reentryIsland )
			freeBranchIsland( reentryIsland );
		if( escapeIsland )
			freeBranchIsland( escapeIsland );
	}

	return err;
}

/*******************************************************************************
*	
*	Implementation
*	
*******************************************************************************/
#pragma mark	-
#pragma mark	(Implementation)

static bool jump_in_range(intptr_t from, intptr_t to) {
  intptr_t field_value = to - from - 5;
  int32_t field_value_32 = field_value;
  return field_value == field_value_32;
}

/*******************************************************************************
	Implementation: Allocates memory for a branch island.
	
	@param	island			<-	The allocated island.
	@result					<-	mach_error_t

	***************************************************************************/

static mach_error_t
allocateBranchIslandAux(
		BranchIsland	**island,
		void *originalFunctionAddress,
		bool forward)
{
	assert( island );
	assert( sizeof( BranchIsland ) <= kPageSize );

	vm_map_t task_self = mach_task_self();
	vm_address_t original_address = (vm_address_t) originalFunctionAddress;
	vm_address_t address = original_address;

	for (;;) {
		vm_size_t vmsize = 0;
		memory_object_name_t object = 0;
		kern_return_t kr = 0;
		vm_region_flavor_t flavor = VM_REGION_BASIC_INFO;
		// Find the region the address is in.
#if __WORDSIZE == 32
		vm_region_basic_info_data_t info;
		mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT;
		kr = vm_region(task_self, &address, &vmsize, flavor,
			       (vm_region_info_t)&info, &info_count, &object);
#else
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
		kr = vm_region_64(task_self, &address, &vmsize, flavor,
				  (vm_region_info_t)&info, &info_count, &object);
#endif
		if (kr != KERN_SUCCESS)
			return kr;
		assert((address & (kPageSize - 1)) == 0);

		// Go to the first page before or after this region
		vm_address_t new_address = forward ? address + vmsize : address - kPageSize;
#if __WORDSIZE == 64
		if(!jump_in_range(original_address, new_address))
			break;
#endif
		address = new_address;

		// Try to allocate this page.
		kr = vm_allocate(task_self, &address, kPageSize, 0);
		if (kr == KERN_SUCCESS) {
			*island = (BranchIsland*) address;
			return err_none;
		}
		if (kr != KERN_NO_SPACE)
			return kr;
	}

	return KERN_NO_SPACE;
}

static mach_error_t
allocateBranchIsland(
		BranchIsland	**island,
		void *originalFunctionAddress)
{
  mach_error_t err =
    allocateBranchIslandAux(island, originalFunctionAddress, true);
  if (!err)
    return err;
  return allocateBranchIslandAux(island, originalFunctionAddress, false);
}


/*******************************************************************************
	Implementation: Deallocates memory for a branch island.
	
	@param	island	->	The island to deallocate.
	@result			<-	mach_error_t

	***************************************************************************/

	mach_error_t
freeBranchIsland(
		BranchIsland	*island )
{
	assert( island );
	assert( (*(long*)&island->instructions[0]) == kIslandTemplate[0] );
	assert( sizeof( BranchIsland ) <= kPageSize );
	return vm_deallocate( mach_task_self(), (vm_address_t) island,
			      kPageSize );
}

/*******************************************************************************
	Implementation: Sets the branch island's target, with an optional
	instruction.
	
	@param	island		->	The branch island to insert target into.
	@param	branchTo	->	The address of the target.
	@param	instruction	->	Optional instruction to execute prior to branch. Set
							to zero for nop.
	@result				<-	mach_error_t

	***************************************************************************/
#if defined(__i386__)
	mach_error_t
setBranchIslandTarget_i386(
	BranchIsland	*island,
	const void		*branchTo,
	char*			instructions )
{

	//	Copy over the template code.
    bcopy( kIslandTemplate, island->instructions, sizeof( kIslandTemplate ) );

	// copy original instructions
	if (instructions) {
		bcopy (instructions, island->instructions + kInstructions, kOriginalInstructionsSize);
	}
	
    // Fill in the address.
    int32_t addressOffset = (char *)branchTo - (island->instructions + kJumpAddress + 4);
    *((int32_t *)(island->instructions + kJumpAddress)) = addressOffset; 

    msync( island->instructions, sizeof( kIslandTemplate ), MS_INVALIDATE );
    return err_none;
}

#elif defined(__x86_64__)
mach_error_t
setBranchIslandTarget_i386(
        BranchIsland	*island,
        const void		*branchTo,
        char*			instructions )
{
    // Copy over the template code.
    bcopy( kIslandTemplate, island->instructions, sizeof( kIslandTemplate ) );

    // Copy original instructions.
    if (instructions) {
        bcopy (instructions, island->instructions, kOriginalInstructionsSize);
    }

    //	Fill in the address.
    *((uint64_t *)(island->instructions + kJumpAddress)) = (uint64_t)branchTo; 
    msync( island->instructions, sizeof( kIslandTemplate ), MS_INVALIDATE );

    return err_none;
}
#endif

	static Boolean 
eatKnownInstructions( 
	unsigned char	*code, 
	uint64_t		*newInstruction,
	int				*howManyEaten, 
	char			*originalInstructions,
	int				*originalInstructionCount, 
	uint8_t			*originalInstructionSizes )
{
	Boolean allInstructionsKnown = true;
	int totalEaten = 0;
	unsigned char* ptr = code;
	int remainsToEat = 5; // a JMP instruction takes 5 bytes
	int instructionIndex = 0;
	
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_input_buffer(&ud_obj, code, 256 /* bogus */);
	
#if defined(__i386__)
	ud_set_mode(&ud_obj, 32);
#elif defined(__x86_64__)
	ud_set_mode(&ud_obj, 64);
#endif 
	
	if (howManyEaten) *howManyEaten = 0;
	if (originalInstructionCount) *originalInstructionCount = 0;
	while (remainsToEat > 0) {
		Boolean curInstructionKnown = false;
		
		unsigned int eaten = ud_disassemble(&ud_obj);
		
		ptr += eaten;
		remainsToEat -= eaten;
		totalEaten += eaten;
		
		if (originalInstructionSizes) originalInstructionSizes[instructionIndex] = eaten;
		instructionIndex += 1;
		if (originalInstructionCount) *originalInstructionCount = instructionIndex;
	}


	if (howManyEaten) *howManyEaten = totalEaten;

	if (originalInstructions) {
		Boolean enoughSpaceForOriginalInstructions = (totalEaten < kOriginalInstructionsSize);
		
		if (enoughSpaceForOriginalInstructions) {
			memset(originalInstructions, 0x90 /* NOP */, kOriginalInstructionsSize); // fill instructions with NOP
			bcopy(code, originalInstructions, totalEaten);
		} else {
			// printf ("Not enough space in island to store original instructions. Adapt the island definition and kOriginalInstructionsSize\n");
			return false;
		}
	}
	
	if (allInstructionsKnown) {
		// save last 3 bytes of first 64bits of codre we'll replace
		uint64_t currentFirst64BitsOfCode = *((uint64_t *)code);
		currentFirst64BitsOfCode = OSSwapInt64(currentFirst64BitsOfCode); // back to memory representation
		currentFirst64BitsOfCode &= 0x0000000000FFFFFFLL; 
		
		// keep only last 3 instructions bytes, first 5 will be replaced by JMP instr
		*newInstruction &= 0xFFFFFFFFFF000000LL; // clear last 3 bytes
		*newInstruction |= (currentFirst64BitsOfCode & 0x0000000000FFFFFFLL); // set last 3 bytes
	}

	return allInstructionsKnown;
}

	static void
fixupInstructions(
	uint32_t	offset,
    void		*instructionsToFix,
	int			instructionCount,
	uint8_t		*instructionSizes )
{
	// The start of "leaq offset(%rip),%rax"
	static const uint8_t LeaqHeader[] = {0x48, 0x8d, 0x05};

	int	index;
	for (index = 0;index < instructionCount;index += 1)
	{
		if (*(uint8_t*)instructionsToFix == 0xE9) // 32-bit jump relative
		{
			uint32_t *jumpOffsetPtr = (uint32_t*)((uintptr_t)instructionsToFix + 1);
			*jumpOffsetPtr += offset;
		}

		// leaq offset(%rip),%rax
		if (memcmp(instructionsToFix, LeaqHeader, 3) == 0) {
			uint32_t *LeaqOffsetPtr = (uint32_t*)((uintptr_t)instructionsToFix + 3);
			*LeaqOffsetPtr += offset;
		}

		// 32-bit call relative to the next addr; pop %eax
		if (*(uint8_t*)instructionsToFix == 0xE8)
		{
			// Just this call is larger than the jump we use, so we
			// know this is the last instruction.
			assert(index == (instructionCount - 1));
			assert(instructionSizes[index] == 6);

                        // Insert "addl $offset, %eax" in the end so that when
                        // we jump to the rest of the function %eax has the
                        // value it would have if eip had been pushed by the
                        // call in its original position.
			uint8_t *op = instructionsToFix;
			op += 6;
			*op = 0x05; // addl
			uint32_t *addImmPtr = (uint32_t*)(op + 1);
			*addImmPtr = offset;
		}

		instructionsToFix = (void*)((uintptr_t)instructionsToFix + instructionSizes[index]);
    }
}

#if defined(__i386__)
__asm(
			".text;"
			".align 2, 0x90;"
			"_atomic_mov64:;"
			"	pushl %ebp;"
			"	movl %esp, %ebp;"
			"	pushl %esi;"
			"	pushl %ebx;"
			"	pushl %ecx;"
			"	pushl %eax;"
			"	pushl %edx;"
	
			// atomic push of value to an address
			// we use cmpxchg8b, which compares content of an address with 
			// edx:eax. If they are equal, it atomically puts 64bit value 
			// ecx:ebx in address. 
			// We thus put contents of address in edx:eax to force ecx:ebx
			// in address
			"	mov		8(%ebp), %esi;"  // esi contains target address
			"	mov		12(%ebp), %ebx;"
			"	mov		16(%ebp), %ecx;" // ecx:ebx now contains value to put in target address
			"	mov		(%esi), %eax;"
			"	mov		4(%esi), %edx;"  // edx:eax now contains value currently contained in target address
			"	lock; cmpxchg8b	(%esi);" // atomic move.
			
			// restore registers
			"	popl %edx;"
			"	popl %eax;"
			"	popl %ecx;"
			"	popl %ebx;"
			"	popl %esi;"
			"	popl %ebp;"
			"	ret"
);
#elif defined(__x86_64__)
void atomic_mov64(
		uint64_t *targetAddress,
		uint64_t value )
{
    *targetAddress = value;
}
#endif
