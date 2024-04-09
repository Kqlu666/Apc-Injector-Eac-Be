TABLE_SEARCH_RESULT
MiFindNodeOrParent(
	IN PMM_AVL_TABLE Table,
	IN ULONG_PTR StartingVpn,
	OUT PMMADDRESS_NODE* NodeOrParent
)

/*++
	Routine Description:
		This routine is used by all of the routines of the generic
		table package to locate the a node in the tree.  It will
		find and return (via the NodeOrParent parameter) the node
		with the given key, or if that node is not in the tree it
		will return (via the NodeOrParent parameter) a pointer to
		the parent.
	Arguments:
		Table - The generic table to search for the key.
		StartingVpn - The starting virtual page number.
		NodeOrParent - Will be set to point to the node containing the
		the key or what should be the parent of the node
		if it were in the tree.  Note that this will *NOT*
		be set if the search result is TableEmptyTree.
	Return Value:
		TABLE_SEARCH_RESULT - TableEmptyTree: The tree was empty.  NodeOrParent
		is *not* altered.
		TableFoundNode: A node with the key is in the tree.
		NodeOrParent points to that node.
		TableInsertAsLeft: Node with key was not found.
		NodeOrParent points to what would
		be parent.  The node would be the
		left child.
		TableInsertAsRight: Node with key was not found.
		NodeOrParent points to what would
		be parent.  The node would be
		the right child.
	Environment:
		Kernel mode.  The PFN lock is held for some of the tables.
--*/

{
	PMMADDRESS_NODE Child;
	PMMADDRESS_NODE NodeToExamine;
	_MMVAD_SHORT* VpnCompare;
	ULONG_PTR       startVpn;
	ULONG_PTR       endVpn;

	if (Table->NumberGenericTableElements == 0)
	{
		return TableEmptyTree;
	}

	NodeToExamine = (PMMADDRESS_NODE)GET_VAD_ROOT(Table);

	for (;;) {

		VpnCompare = (_MMVAD_SHORT*)NodeToExamine;
		startVpn = VpnCompare->StartingVpn;
		endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
		startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
		endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

		//
		// Compare the buffer with the key in the tree element.
		//

		if (StartingVpn < startVpn) {

			Child = NodeToExamine->LeftChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsLeft;
			}
		}
		else if (StartingVpn <= endVpn) {

			//
			// This is the node.
			//

			*NodeOrParent = NodeToExamine;
			return TableFoundNode;
		}
		else {

			Child = NodeToExamine->RightChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsRight;
			}
		}

	};
}

//TABLE_SEARCH_RESULT MiFindNodeOrParent(IN PMM_AVL_TABLE Table, IN ULONG_PTR StartingVpn, OUT PMMADDRESS_NODE* NodeOrParent);

NTSTATUS BBFindVAD(IN PEPROCESS pProcess, IN ULONG_PTR address, OUT _MMVAD_SHORT** pResult)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR vpnStart = address >> PAGE_SHIFT;

	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)pProcess + VadRootOffset);
	PMM_AVL_NODE pNode = GET_VAD_ROOT(pTable);

	// Search VAD
	if (MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode)
	{
		*pResult = (_MMVAD_SHORT*)pNode;
	}
	else
	{
		//DbgPrint("[FACE]: %s: VAD entry for address 0x%p not found\n", __FUNCTION__, address);
		status = STATUS_NOT_FOUND;
	}

	return status;
}

NTSTATUS BBUnlinkVAD(IN PEPROCESS pProcess, IN ULONG_PTR address)
{
	NTSTATUS status = STATUS_SUCCESS;
	_MMVAD_SHORT* pVadShort = NULL;

	status = BBFindVAD(pProcess, address, &pVadShort);
	if (!NT_SUCCESS(status))
		return STATUS_UNSUCCESSFUL;

	//DbgPrint("[FACE] Vad found! :: 0x%p\n", pVadShort);

	// Erase image name
	if (pVadShort->u.VadFlags.VadType == VadImageMap)
	{
		PMMVAD pVadLong = (PMMVAD)pVadShort;
		if (pVadLong->Subsection && pVadLong->Subsection->ControlArea && pVadLong->Subsection->ControlArea->FilePointer.Object)
		{
			PFILE_OBJECT pFile = (PFILE_OBJECT)(pVadLong->Subsection->ControlArea->FilePointer.Value & ~0xF);
			pFile->FileName.Buffer[0] = L'\0';
			pFile->FileName.Length = 0;
		}
		else
			return STATUS_INVALID_ADDRESS;
	}
	// Make NO_ACCESS
	else if (pVadShort->u.VadFlags.VadType == VadDevicePhysicalMemory)
	{
		pVadShort->u.VadFlags.Protection = 0;
	}
	// Invalid VAD type
	else
	{
		//DbgPrint("[FACE] Invalid VAD type: %d\n", pVadShort->u.VadFlags.VadType);
		status = STATUS_INVALID_PARAMETER;
	}

	return status;
}
