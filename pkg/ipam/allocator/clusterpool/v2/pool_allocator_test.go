// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"math/big"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func TestPoolAllocator(t *testing.T) {
	p := NewPoolAllocator()
	err := p.AddPool("default",
		[]string{"10.100.0.0/16", "10.200.0.0/16"}, 24,
		[]string{"fd00:100::/80", "fc00:100::/80"}, 96,
	)
	assert.NoError(t, err)

	// node1 is a node which has some previously allocated CIDRs
	node1 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node1",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool: "default",
							Needed: ipamTypes.IPAMPoolDemand{
								IPv4Addrs: 10,
								IPv6Addrs: 10,
							},
						},
					},
					Allocated: []ipamTypes.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []string{
								"fd00:100:0:0:0:10::/96",
								"10.100.20.0/24",
								"10.100.10.0/24",
							},
						},
					},
				},
			},
		},
	}
	// node2 is a new node which needs a fresh allocation
	node2 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node2",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Requested: []ipamTypes.IPAMPoolRequest{
						{
							Pool: "default",
							Needed: ipamTypes.IPAMPoolDemand{
								IPv4Addrs: 10,
								IPv6Addrs: 10,
							},
						},
					},
				},
			},
		},
	}
	// node3 is a new node which is attempting to steal a CIDR from node1
	node3 := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node3",
		},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pools: ipamTypes.IPAMPoolSpec{
					Allocated: []ipamTypes.IPAMPoolAllocation{
						{
							Pool: "default",
							CIDRs: []string{
								"10.100.10.0/24", // already allocated to node1
							},
						},
					},
				},
			},
		},
	}
	// node1 has some pre-allocated pools that need to be restored
	err = p.AllocateToNode(node1)
	assert.Error(t, errAllocatorNotReady{}, err)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []string{ // must be sorted
				"10.100.10.0/24",
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}, p.AllocatedPools(node1.Name))

	// node2 must not allocate before restoration has finished
	err = p.AllocateToNode(node2)
	assert.Error(t, errAllocatorNotReady{}, err)
	assert.Empty(t, p.AllocatedPools(node2.Name))

	// node3 must not steal the restored CIDR from node1
	err = p.AllocateToNode(node3)
	assert.Error(t, errAllocatorNotReady{}, err)
	assert.Empty(t, p.AllocatedPools(node3.Name))

	// Mark as ready
	p.RestoreFinished()

	// The following is a no-op, but should not return any errors
	err = p.AllocateToNode(node1)
	assert.NoError(t, err)
	node1.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node1.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []string{ // must be sorted
				"10.100.10.0/24",
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}, node1.Spec.IPAM.Pools.Allocated)

	// The following should allocate one IPv4 and IPv6 CIDR each to node2
	err = p.AllocateToNode(node2)
	assert.NoError(t, err)
	node2.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node2.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []string{
				"10.100.0.0/24",
				"fd00:100::/96",
			},
		},
	}, node2.Spec.IPAM.Pools.Allocated)

	// The following should be rejected, because the CIDR is owned by node1
	err = p.AllocateToNode(node3)
	assert.EqualError(t, err, "unable to reuse from pool default: cidr 10.100.10.0/24 has already been allocated")
	assert.Empty(t, p.AllocatedPools(node3.Name))

	// Release 10.100.10.0/24 from node1
	node1.Spec.IPAM.Pools.Allocated = []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []string{
				"10.100.20.0/24",
				"fd00:100::10:0:0/96",
			},
		},
	}
	err = p.AllocateToNode(node1)
	assert.NoError(t, err)
	assert.Equal(t, node1.Spec.IPAM.Pools.Allocated, p.AllocatedPools(node1.Name))

	// node3 can now allocate 10.100.10.0/24
	err = p.AllocateToNode(node3)
	assert.NoError(t, err)
	node1.Spec.IPAM.Pools.Allocated = p.AllocatedPools(node3.Name)
	assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
		{
			Pool: "default",
			CIDRs: []string{
				"10.100.10.0/24",
			},
		},
	}, node3.Spec.IPAM.Pools.Allocated)

}

func Test_addrsInPrefix(t *testing.T) {
	mustParseBigInt := func(s string) *big.Int {
		r := new(big.Int)
		r.SetString(s, 0)
		return r
	}

	tests := []struct {
		name string
		args netip.Prefix
		want *big.Int
	}{
		{
			name: "ipv4",
			args: netip.MustParsePrefix("10.0.0.0/24"),
			want: big.NewInt(254),
		},
		{
			name: "ipv6",
			args: netip.MustParsePrefix("f00d::/48"),
			want: mustParseBigInt("1208925819614629174706174"),
		},
		{
			name: "zero",
			args: netip.Prefix{},
			want: big.NewInt(0),
		},
		{
			name: "two",
			args: netip.MustParsePrefix("10.0.0.0/30"),
			want: big.NewInt(2),
		},
		{
			name: "underflow /31",
			args: netip.MustParsePrefix("10.0.0.0/31"),
			want: big.NewInt(0),
		},
		{
			name: "underflow /32",
			args: netip.MustParsePrefix("10.0.0.0/32"),
			want: big.NewInt(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addrsInPrefix(tt.args); got.Cmp(tt.want) != 0 {
				t.Errorf("addrsInPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
